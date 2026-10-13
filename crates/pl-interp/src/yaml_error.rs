//! Сообщения разборщика YAML по-русски. Место ошибки и выдержка из текста остаются как есть:
//! переводится только фраза о причине. Незнакомая фраза не трогается.

/// Хвост «, expected one of a, b» — перечень допустимого.
fn allowed(tail: &str) -> String {
    if let Some(list) = tail.strip_prefix(", expected one of ") {
        format!("; допустимые: {list}")
    } else if let Some(one) = tail.strip_prefix(", expected ") {
        format!("; допустимо: {}", one.replace('`', ""))
    } else {
        String::new()
    }
}

fn phrase(msg: &str) -> String {
    let named = |prefix: &str| {
        msg.strip_prefix(prefix)
            .and_then(|rest| rest.split_once('`'))
    };
    if let Some((name, tail)) = named("unknown field `") {
        return format!("неизвестный ключ «{name}»{}", allowed(tail));
    }
    if let Some((name, tail)) = named("unknown variant `") {
        return format!("неизвестное значение «{name}»{}", allowed(tail));
    }
    if let Some((name, _)) = named("missing field `") {
        return format!("нет обязательного ключа «{name}»");
    }
    if let Some(rest) = msg.strip_prefix("duplicate mapping key: ") {
        let name = rest.split_once(',').map_or(rest, |(name, _)| name);
        return format!("ключ «{name}» повторяется");
    }
    if msg.starts_with("budget breached: A") {
        return "якоря и ссылки YAML (&имя, *имя) не поддерживаются".to_owned();
    }
    if msg.starts_with("budget breached") || msg == "recursion limit exceeded" {
        return "описание слишком сложное: превышен предел вложенности или размера".to_owned();
    }
    if msg.starts_with("unexpected end of input") {
        return "текст пуст или оборван".to_owned();
    }
    if let Some(kind) = msg.strip_prefix("invalid ")
        && kind.len() <= 4
        && kind.starts_with(['u', 'i'])
    {
        return "здесь нужно целое число в допустимых пределах".to_owned();
    }
    match msg {
        "expected mapping start" => "здесь нужен набор «ключ: значение»",
        "expected sequence start" => "здесь нужен список",
        "expected string scalar" => "здесь нужно одно значение, а не список и не набор ключей",
        "tabs disallowed within this context (block indentation)" => {
            "отступы — только пробелами, табуляция не допускается"
        }
        "invalid indentation in multiline quoted scalar" => {
            "строка в кавычках не закрыта или у её продолжения неверный отступ"
        }
        other => other,
    }
    .to_owned()
}

/// Текст ошибки разборщика: «строка N, столбец M: причина» и выдержка с указателем.
pub(crate) fn localized(raw: &str) -> String {
    let mut out = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        if index == 0 {
            let placed = line
                .strip_prefix("error: line ")
                .and_then(|rest| rest.split_once(" column "))
                .and_then(|(row, rest)| rest.split_once(": ").map(|(col, msg)| (row, col, msg)));
            out.push(match placed {
                Some((row, col, msg)) => format!("строка {row}, столбец {col}: {}", phrase(msg)),
                None => phrase(line),
            });
        } else if let Some((lead, msg)) = line.split_once("^ ") {
            // Строка с указателем повторяет причину под выдержкой.
            out.push(format!("{lead}^ {}", phrase(msg)));
        } else {
            out.push(line.to_owned());
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::localized;

    #[test]
    fn place_and_reason_are_translated_and_the_excerpt_is_kept() {
        let raw = "error: line 3 column 1: unknown field `exec`, expected one of format, scope\n --> <input>:3:1\n  |\n3 | exec: \"rm -rf /\"\n  | ^ unknown field `exec`, expected one of format, scope\n  |";
        let text = localized(raw);
        assert!(
            text.starts_with(
                "строка 3, столбец 1: неизвестный ключ «exec»; допустимые: format, scope\n"
            ),
            "{text}"
        );
        assert!(text.contains("3 | exec: \"rm -rf /\""));
        assert!(text.contains("  | ^ неизвестный ключ «exec»; допустимые: format, scope"));
        assert!(!text.contains("unknown field"));
    }

    #[test]
    fn common_mistakes_have_russian_reasons() {
        let cases = [
            (
                "unknown variant `u9`, expected one of u8, u16be",
                "неизвестное значение «u9»; допустимые: u8, u16be",
            ),
            ("missing field `name`", "нет обязательного ключа «name»"),
            (
                "duplicate mapping key: id, set DuplicateKeyPolicy in Options if acceptable",
                "ключ «id» повторяется",
            ),
            (
                "budget breached: Anchors { anchors: 1 }",
                "якоря и ссылки YAML (&имя, *имя) не поддерживаются",
            ),
            (
                "recursion limit exceeded",
                "описание слишком сложное: превышен предел вложенности или размера",
            ),
            (
                "invalid u32",
                "здесь нужно целое число в допустимых пределах",
            ),
            ("expected sequence start", "здесь нужен список"),
            (
                "tabs disallowed within this context (block indentation)",
                "отступы — только пробелами, табуляция не допускается",
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                localized(&format!("error: line 2 column 5: {raw}")),
                format!("строка 2, столбец 5: {expected}")
            );
        }
        assert_eq!(
            localized("unexpected end of input at line 1, column 1"),
            "текст пуст или оборван"
        );
    }

    #[test]
    fn an_unfamiliar_reason_is_left_as_is() {
        let raw = "error: line 1 column 2: something new\n1 | a^ b";
        assert_eq!(
            localized(raw),
            "строка 1, столбец 2: something new\n1 | a^ b"
        );
    }
}
