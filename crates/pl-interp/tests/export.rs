//! Экспорт описания в диссектор Wireshark: что попадает в текст и когда выгрузка невозможна.
//! Сам диссектор сверяется с `apply` через tshark в тестах командной строки.

use pl_interp::Interpretation;
use pl_interp::export::{ExportError, wireshark_lua};

const GROUPS: &str = r#"
format: protoledger/interpretation@1
scope: { direction: any, filter: "dst_port == 5020 || src_port == 5020" }
framing: { kind: length_prefixed, length: { at: 2, type: u8, adjust: 3 }, sync: "a65c", status: rule }
messages:
  - id: batch
    when: "n > 0"
    fields:
      - { name: sig, at: 0, type: bytes, len: 2, expect: "a65c", status: rule }
      - { name: body, at: 2, type: u8, status: rule }
      - { name: n, at: 3, type: u8, status: rule }
      - name: items
        at: 4
        type: bytes
        status: rule
        repeat:
          count: "n"
          fields:
            - { name: time, at: 0, type: u16le, status: rule }
            - { name: flag, at: 2, type: u8, status: hypothesis, hypothesis: H1 }
  - id: empty
    fields:
      - { name: sig, at: 0, type: bytes, len: 2, status: rule }
hypotheses:
  - { id: H1, statement: "flag — признак" }
"#;

const VARINT: &str = r#"
format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 1, type: varint }, status: rule }
messages:
  - id: publish
    when: "kind == 3"
    fields:
      - { name: kind, at: 0, type: u8, mask: 0xf0, status: rule }
      - { name: remaining, at: 1, type: varint, status: rule }
      - { name: topic_len, at: next, type: u16be, status: rule }
      - { name: topic, at: next, type: string, len: "topic_len", status: rule }
      - { name: payload, at: next, type: bytes, len: to_end, status: rule }
checks:
  - { id: C1, kind: structural, expr: "sum8(0, 1) >= 0" }
"#;

fn lua(text: &str) -> String {
    wireshark_lua(&Interpretation::parse(text).unwrap(), "demo").unwrap()
}

#[test]
fn dissector_carries_framing_messages_fields_and_ports() {
    let code = lua(GROUPS);
    assert!(code.contains(r#"local proto = Proto("demo", "demo (protoledger)")"#));
    // Длина сообщения — поле длины плюс поправка, заголовок — до конца поля длины.
    assert!(
        code.contains("local total = buf(offset + 2, 1):uint() + (3)"),
        "{code}"
    );
    assert!(code.contains("dissect_tcp_pdus(buf, tree, 3, message_length, dissect_message)"));
    // Порт берётся из условия области.
    assert!(code.contains("tcp:add(5020, proto)"));
    assert!(!code.contains("add_for_decode_as"));
    // Поля группы — со своими именами фильтров, порядок байтов сохраняется.
    assert!(code.contains(
        r#"F["batch.items.time"] = ProtoField.uint16("demo.batch.items.time", "time", base.DEC)"#
    ));
    assert!(code.contains(r#"sub:add_le(F["batch.items.time"], r)"#));
    assert!(code.contains("origin = first + i * 3"));
    assert!(code.contains(r#"return ((v["n"] > (0))) == true"#));
    // Сообщение без условия подходит всегда.
    assert!(code.contains("W[1] = function(buf, pinfo, len)\n  return true\nend"));
    assert!(code.contains("for i = 0, 1 do"));
    assert!(code.contains("Полей со статусом «гипотеза» или «неизвестно» в описании: 0"));
}

#[test]
fn varint_mask_and_fields_after_variable_ones_are_carried() {
    let code = lua(VARINT);
    assert!(
        code.contains("local total = varint_length(buf, offset + 1, 1 + (0))"),
        "{code}"
    );
    assert!(code.contains("if not total then return 0 end"));
    assert!(code.contains(r#"ProtoField.uint8("demo.publish.kind", "kind", base.DEC, nil, 0xf0)"#));
    // В условии — биты маски, сдвинутые к младшему, как значение поля в описании.
    assert!(code.contains(r#"v["kind"] = math.floor(r:uint() / 16) % 16"#));
    assert!(code.contains("size, value = varint(buf, at, len)"));
    assert!(code.contains(r#"size = v["topic_len"]"#));
    assert!(code.contains("size = at and (len - at)"));
    // Без порта в описании протокол выбирается вручную.
    assert!(code.contains("add_for_decode_as"));
    // Проверки в диссектор не попадают.
    assert!(!code.contains("sum8"));
}

#[test]
fn a_condition_with_functions_never_matches_in_the_dissector() {
    let code = lua(&VARINT.replace("kind == 3", "sum8(0, 1) == 48"));
    assert!(
        code.contains("return false -- условие описания не переносится в диссектор"),
        "{code}"
    );
}

#[test]
fn unsupported_framing_and_bad_names_are_refused() {
    let delimiter = r#"
format: protoledger/interpretation@1
framing: { kind: delimiter, bytes: "0d0a", status: rule }
messages:
  - id: line
    fields:
      - { name: text, at: 0, type: string, len: to_end, status: rule }
"#;
    let it = Interpretation::parse(delimiter).unwrap();
    assert_eq!(wireshark_lua(&it, "demo"), Err(ExportError::Framing));

    let it = Interpretation::parse(GROUPS).unwrap();
    for name in ["", "Demo", "1demo", "de-mo", "протокол", &"a".repeat(33)] {
        assert_eq!(wireshark_lua(&it, name), Err(ExportError::Name), "{name}");
    }
}

#[test]
fn text_from_the_description_cannot_break_out_of_a_lua_string() {
    // Имена в описании ограничены, а строки в условиях — произвольные.
    let when = r#"when: "src_ip == 'a\" .. os.exit() .. \"'""#;
    let code = lua(&VARINT.replace(r#"when: "kind == 3""#, when));
    assert!(
        code.contains(r#"(tostring(pinfo.src) == "a\" .. os.exit() .. \"")"#),
        "{code}"
    );
}
