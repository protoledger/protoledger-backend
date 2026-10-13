//! Экспорт описания в диссектор Wireshark на Lua: тот же фрейминг, типы сообщений и поля,
//! чтобы результат исследования открывался в привычном инструменте.
//!
//! Переносится разбор: границы сообщений, условия `when`, поля со смещениями и длинами,
//! повторяющиеся группы. Проверки, гипотезы и их тесты в диссектор не попадают.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::expr::{Expr, LuaNames};
use crate::schema::{
    FieldDef, FieldType, FramingKind, Interpretation, Len, MessageDef, Offset, Status,
};

/// Почему описание нельзя выгрузить.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExportError {
    #[error(
        "диссектор строится для фрейминга length_prefixed и fixed; разделитель и сигнатура не поддержаны"
    )]
    Framing,
    #[error("имя протокола — латинские буквы, цифры и подчёркивания, не длиннее 32 символов")]
    Name,
}

fn ident(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn lua_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Имена в выражениях диссектора: значения полей лежат в таблице `v`, длина сообщения — `len`.
struct Names;

impl LuaNames for Names {
    fn name(&self, name: &str) -> Option<String> {
        Some(match name {
            "message.len" => "len".to_owned(),
            "src_port" => "pinfo.src_port".to_owned(),
            "dst_port" => "pinfo.dst_port".to_owned(),
            "src_ip" => "tostring(pinfo.src)".to_owned(),
            "dst_ip" => "tostring(pinfo.dst)".to_owned(),
            other => format!("v[{}]", lua_string(other)),
        })
    }
}

fn expression(text: &str) -> Option<String> {
    Expr::parse(text).ok()?.to_lua(&Names)
}

/// Тип поля Wireshark и способ прочитать значение для выражений (`nil` — значение не нужно).
fn proto_field(f: &FieldDef, abbr: &str) -> String {
    let label = lua_string(&f.name);
    let abbr = lua_string(abbr);
    let mask = f
        .mask
        .map(|m| format!(", nil, 0x{m:x}"))
        .unwrap_or_default();
    match f.ty {
        FieldType::U8 => format!("ProtoField.uint8({abbr}, {label}, base.DEC{mask})"),
        FieldType::U16be | FieldType::U16le => {
            format!("ProtoField.uint16({abbr}, {label}, base.DEC{mask})")
        }
        FieldType::U32be | FieldType::U32le => {
            format!("ProtoField.uint32({abbr}, {label}, base.DEC{mask})")
        }
        FieldType::U64be | FieldType::U64le => {
            format!("ProtoField.uint64({abbr}, {label}, base.DEC)")
        }
        FieldType::I8 => format!("ProtoField.int8({abbr}, {label}, base.DEC)"),
        FieldType::I16be | FieldType::I16le => {
            format!("ProtoField.int16({abbr}, {label}, base.DEC)")
        }
        FieldType::I32be | FieldType::I32le => {
            format!("ProtoField.int32({abbr}, {label}, base.DEC)")
        }
        FieldType::I64be | FieldType::I64le => {
            format!("ProtoField.int64({abbr}, {label}, base.DEC)")
        }
        FieldType::F32be | FieldType::F32le => format!("ProtoField.float({abbr}, {label})"),
        FieldType::F64be | FieldType::F64le => format!("ProtoField.double({abbr}, {label})"),
        FieldType::String => format!("ProtoField.string({abbr}, {label})"),
        FieldType::Varint => format!("ProtoField.uint32({abbr}, {label}, base.DEC)"),
        // Двоично-десятичное число в шестнадцатеричном виде читается как есть.
        FieldType::Bcd | FieldType::Bytes | FieldType::Unknown => {
            format!("ProtoField.bytes({abbr}, {label})")
        }
    }
}

fn little_endian(ty: FieldType) -> bool {
    ty.int().is_some_and(|t| !t.big_endian()) || matches!(ty, FieldType::F32le | FieldType::F64le)
}

/// Выражение Lua, читающее число из диапазона `r` для таблицы значений.
fn reader(ty: FieldType) -> Option<&'static str> {
    Some(match ty {
        FieldType::U8 | FieldType::U16be | FieldType::U32be => "r:uint()",
        FieldType::U16le | FieldType::U32le => "r:le_uint()",
        FieldType::I8 | FieldType::I16be | FieldType::I32be => "r:int()",
        FieldType::I16le | FieldType::I32le => "r:le_int()",
        FieldType::U64be => "r:uint64():tonumber()",
        FieldType::U64le => "r:le_uint64():tonumber()",
        FieldType::I64be => "r:int64():tonumber()",
        FieldType::I64le => "r:le_int64():tonumber()",
        FieldType::String => "r:string()",
        _ => return None,
    })
}

fn fixed_size(f: &FieldDef) -> Option<u64> {
    crate::schema::fixed_size(f)
}

/// Код одного поля: место, размер, добавление в дерево, значение для выражений, сдвиг курсора.
fn field_code(out: &mut String, f: &FieldDef, var: &str, indent: &str, key: &str) {
    let at = match f.at.offset() {
        Some(Offset::FromStart(n)) => format!("origin + {n}"),
        Some(Offset::FromEnd(n)) => format!("len - {n}"),
        Some(Offset::Next) | None => "pos".to_owned(),
    };
    let _ = writeln!(out, "{indent}at = {at}");
    if f.ty == FieldType::Varint {
        let _ = writeln!(out, "{indent}size, value = varint(buf, at, len)");
    } else {
        let size = match (&f.len, fixed_size(f)) {
            (_, Some(n)) => n.to_string(),
            (Some(Len::Text(t)), _) if t == "to_end" => "at and (len - at)".to_owned(),
            (Some(Len::Text(t)), _) => expression(t).unwrap_or_else(|| "nil".to_owned()),
            _ => "nil".to_owned(),
        };
        let _ = writeln!(out, "{indent}size = {size}");
        let _ = writeln!(out, "{indent}value = nil");
    }
    let _ = writeln!(
        out,
        "{indent}if at and size and at >= 0 and size >= 0 and at + size <= len then"
    );
    // Диапазон нулевой длины Wireshark не принимает: пустое поле в дерево не добавляется.
    let _ = writeln!(out, "{indent}  if size > 0 then");
    let _ = writeln!(out, "{indent}    local r = buf(at, size)");
    if f.ty == FieldType::Varint {
        let _ = writeln!(out, "{indent}    sub:add({var}, r, value)");
    } else if little_endian(f.ty) {
        let _ = writeln!(out, "{indent}    sub:add_le({var}, r)");
    } else {
        let _ = writeln!(out, "{indent}    sub:add({var}, r)");
    }
    if let (Some(read), true) = (reader(f.ty), f.ty != FieldType::Varint) {
        let read = match f.mask {
            // Биты маски, сдвинутые к младшему, — как значение поля в описании.
            Some(mask) if mask != 0 => {
                let shift = mask.trailing_zeros();
                let width = 64 - (mask >> shift).leading_zeros();
                format!(
                    "math.floor({read} / {}) % {}",
                    1u64 << shift,
                    1u128 << width
                )
            }
            _ => read.to_owned(),
        };
        let _ = writeln!(out, "{indent}    value = {read}");
    }
    let _ = writeln!(out, "{indent}  end");
    let _ = writeln!(out, "{indent}  v[{key}] = value");
    let _ = writeln!(out, "{indent}  pos = at + size");
    let _ = writeln!(out, "{indent}else");
    let _ = writeln!(out, "{indent}  pos = nil");
    let _ = writeln!(out, "{indent}end");
}

fn message_code(out: &mut String, index: usize, m: &MessageDef) {
    // Функции лежат в таблицах: у Lua предел в 200 локальных переменных на файл.
    let _ = writeln!(out, "D[{index}] = function(buf, sub, v, len)");
    let _ = writeln!(
        out,
        "  local origin, pos, at, size, value = 0, 0, nil, nil, nil"
    );
    for f in &m.fields {
        let var = format!("F[{}]", lua_string(&format!("{}.{}", m.id, f.name)));
        let Some(group) = &f.repeat else {
            field_code(out, f, &var, "  ", &lua_string(&f.name));
            continue;
        };
        // Повторяющаяся группа: элементы одного размера, поля — со смещениями от начала элемента.
        let Some(item) = group.item_size() else {
            continue;
        };
        let count = match &group.count {
            Len::Fixed(n) => n.to_string(),
            Len::Text(t) => expression(t).unwrap_or_else(|| "0".to_owned()),
        };
        let start = match f.at.offset() {
            Some(Offset::FromStart(n)) => n.to_string(),
            Some(Offset::FromEnd(n)) => format!("len - {n}"),
            Some(Offset::Next) | None => "pos".to_owned(),
        };
        let _ = writeln!(out, "  local first, count = {start}, {count}");
        let _ = writeln!(out, "  pos = nil");
        let _ = writeln!(
            out,
            "  if first and type(count) == \"number\" and count >= 0 and first + count * {item} <= len then"
        );
        let _ = writeln!(out, "    for i = 0, count - 1 do");
        let _ = writeln!(out, "      origin = first + i * {item}");
        for child in &group.fields {
            let var = format!(
                "F[{}]",
                lua_string(&format!("{}.{}.{}", m.id, f.name, child.name))
            );
            let key = format!(
                "{} .. i .. {}",
                lua_string(&format!("{}.", f.name)),
                lua_string(&format!(".{}", child.name))
            );
            field_code(out, child, &var, "      ", &key);
        }
        let _ = writeln!(out, "    end");
        let _ = writeln!(out, "    origin = 0");
        let _ = writeln!(out, "    pos = first + count * {item}");
        let _ = writeln!(out, "  end");
    }
    let _ = writeln!(out, "end\n");
}

/// Условие `when`: читаются только поля с известным местом и размером.
fn when_code(out: &mut String, index: usize, m: &MessageDef) {
    let _ = writeln!(out, "W[{index}] = function(buf, pinfo, len)");
    let Some(when) = &m.when else {
        let _ = writeln!(out, "  return true\nend\n");
        return;
    };
    let _ = writeln!(out, "  local v = {{}}");
    for f in &m.fields {
        let (Some(Offset::FromStart(at)), Some(size), Some(read)) =
            (f.at.offset(), fixed_size(f), reader(f.ty))
        else {
            continue;
        };
        let read = match f.mask {
            Some(mask) if mask != 0 => {
                let shift = mask.trailing_zeros();
                let width = 64 - (mask >> shift).leading_zeros();
                format!(
                    "math.floor({read} / {}) % {}",
                    1u64 << shift,
                    1u128 << width
                )
            }
            _ => read.to_owned(),
        };
        let _ = writeln!(
            out,
            "  if {at} + {size} <= len then local r = buf({at}, {size}); v[{}] = {read} end",
            lua_string(&f.name)
        );
    }
    match expression(when) {
        Some(code) => {
            let _ = writeln!(out, "  return ({code}) == true");
        }
        None => {
            let _ = writeln!(
                out,
                "  return false -- условие описания не переносится в диссектор"
            );
        }
    }
    let _ = writeln!(out, "end\n");
}

/// Порты из условия области: по ним диссектор регистрируется сам.
fn ports(it: &Interpretation) -> BTreeSet<u16> {
    it.scope
        .filter
        .as_deref()
        .and_then(|f| Expr::parse(f).ok())
        .map(|e| e.port_literals())
        .unwrap_or_default()
}

const HELPERS: &str = r#"-- Число переменного размера: по 7 бит в байте, младшие первыми; размер и значение.
local function varint(buf, at, len)
  local value, i = 0, 0
  while at and at + i < len and i < 9 do
    local b = buf(at + i, 1):uint()
    value = value + (b % 128) * 2 ^ (7 * i)
    i = i + 1
    if b < 128 then return i, value end
  end
  return nil, nil
end

-- Размер сообщения с полем длины переменного размера; nil — поле ещё не дочитано.
local function varint_length(buf, at, extra)
  local size, value = varint(buf, at, buf:len())
  if not size then return nil end
  return value + size + extra
end

"#;

/// Диссектор Wireshark для описания `it`. `name` — имя протокола в фильтрах отображения.
pub fn wireshark_lua(it: &Interpretation, name: &str) -> Result<String, ExportError> {
    let valid = !name.is_empty()
        && name.len() <= 32
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !valid {
        return Err(ExportError::Name);
    }
    let framing = &it.framing;
    let (header, length) = match (framing.kind, &framing.length, framing.size) {
        (FramingKind::LengthPrefixed, Some(spec), _) => match spec.ty.int() {
            Some(int) => {
                let read = match (int.size(), int.big_endian(), int.signed()) {
                    (8, true, _) => "uint64():tonumber()",
                    (8, false, _) => "le_uint64():tonumber()",
                    (_, true, false) => "uint()",
                    (_, false, false) => "le_uint()",
                    (_, true, true) => "int()",
                    (_, false, true) => "le_int()",
                };
                (
                    u64::from(spec.at) + int.size() as u64,
                    format!(
                        "buf(offset + {}, {}):{read} + ({})",
                        spec.at,
                        int.size(),
                        spec.adjust
                    ),
                )
            }
            None => (
                u64::from(spec.at) + 1,
                format!(
                    "varint_length(buf, offset + {}, {} + ({}))",
                    spec.at, spec.at, spec.adjust
                ),
            ),
        },
        (FramingKind::Fixed, _, Some(size)) => (u64::from(size), size.to_string()),
        _ => return Err(ExportError::Framing),
    };

    let mut out = String::new();
    let _ = writeln!(
        out,
        "-- Диссектор Wireshark, выгруженный из описания протокола protoledger."
    );
    let _ = writeln!(
        out,
        "-- Положите файл в папку личных плагинов Wireshark или запустите: tshark -X lua_script:<файл> -r <запись>."
    );
    let _ = writeln!(
        out,
        "-- Переносится разбор сообщений и полей; проверки и гипотезы остаются в описании.\n"
    );
    let _ = writeln!(
        out,
        "local proto = Proto({}, {})",
        lua_string(name),
        lua_string(&format!("{name} (protoledger)"))
    );
    let _ = writeln!(out, "local F = {{}}");
    let _ = writeln!(
        out,
        "F[\"\"] = ProtoField.string({}, \"message\")",
        lua_string(&format!("{name}.message"))
    );
    for m in &it.messages {
        for f in &m.fields {
            if let Some(group) = &f.repeat {
                for child in &group.fields {
                    let key = format!("{}.{}.{}", m.id, f.name, child.name);
                    let abbr = format!(
                        "{name}.{}.{}.{}",
                        ident(&m.id),
                        ident(&f.name),
                        ident(&child.name)
                    );
                    let _ = writeln!(
                        out,
                        "F[{}] = {}",
                        lua_string(&key),
                        proto_field(child, &abbr)
                    );
                }
                continue;
            }
            let key = format!("{}.{}", m.id, f.name);
            let abbr = format!("{name}.{}.{}", ident(&m.id), ident(&f.name));
            let _ = writeln!(out, "F[{}] = {}", lua_string(&key), proto_field(f, &abbr));
        }
    }
    let _ = writeln!(out, "local list = {{}}");
    let _ = writeln!(out, "for _, f in pairs(F) do list[#list + 1] = f end");
    let _ = writeln!(out, "proto.fields = list");
    let _ = writeln!(out, "local W, D, ID = {{}}, {{}}, {{}}\n");

    out.push_str(HELPERS);

    for (i, m) in it.messages.iter().enumerate() {
        let _ = writeln!(out, "ID[{i}] = {}", lua_string(&m.id));
        when_code(&mut out, i, m);
        message_code(&mut out, i, m);
    }

    let _ = writeln!(out, "local function dissect_message(buf, pinfo, tree)");
    let _ = writeln!(out, "  local len = buf:len()");
    let _ = writeln!(out, "  pinfo.cols.protocol = {}", lua_string(name));
    let _ = writeln!(out, "  local sub = tree:add(proto, buf())");
    // Первый тип, чьё условие выполнилось; ошибка в условии — «не подошло».
    let _ = writeln!(out, "  for i = 0, {} do", it.messages.len() as i64 - 1);
    let _ = writeln!(
        out,
        "    if select(2, pcall(W[i], buf, pinfo, len)) == true then"
    );
    let _ = writeln!(out, "      sub:add(F[\"\"], buf(), ID[i])");
    let _ = writeln!(out, "      sub:append_text(\": \" .. ID[i])");
    let _ = writeln!(out, "      pcall(D[i], buf, sub, {{}}, len)");
    let _ = writeln!(out, "      break");
    let _ = writeln!(out, "    end");
    let _ = writeln!(out, "  end");
    let _ = writeln!(out, "  return len");
    let _ = writeln!(out, "end\n");

    let _ = writeln!(out, "local function message_length(buf, pinfo, offset)");
    let _ = writeln!(out, "  local total = {length}");
    // Ноль — «нужен ещё сегмент»; длина меньше заголовка — сообщение из одного заголовка.
    let _ = writeln!(out, "  if not total then return 0 end");
    let _ = writeln!(out, "  if total < {header} then return {header} end");
    let _ = writeln!(out, "  return total");
    let _ = writeln!(out, "end\n");

    let _ = writeln!(out, "function proto.dissector(buf, pinfo, tree)");
    let _ = writeln!(
        out,
        "  dissect_tcp_pdus(buf, tree, {header}, message_length, dissect_message)"
    );
    let _ = writeln!(out, "  return buf:len()");
    let _ = writeln!(out, "end\n");

    let ports = ports(it);
    if ports.is_empty() {
        let _ = writeln!(
            out,
            "-- В описании нет порта: выберите протокол через «Декодировать как…»."
        );
        let _ = writeln!(
            out,
            "pcall(function() DissectorTable.get(\"tcp.port\"):add_for_decode_as(proto) end)"
        );
    } else {
        let _ = writeln!(out, "local tcp = DissectorTable.get(\"tcp.port\")");
        for port in ports {
            let _ = writeln!(out, "tcp:add({port}, proto)");
        }
    }
    // Поле без статуса «правило» — гипотеза или неизвестная зона: напоминание в конце файла.
    let unsure = it
        .messages
        .iter()
        .flat_map(|m| &m.fields)
        .filter(|f| f.status != Status::Rule)
        .count();
    let _ = writeln!(
        out,
        "\n-- Полей со статусом «гипотеза» или «неизвестно» в описании: {unsure}. Диссектор показывает разбор, а не доказывает его."
    );
    Ok(out)
}
