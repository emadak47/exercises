#[derive(Debug)]
struct Element {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Element>,
}

type ParseResult<'a, Output> = Result<(&'a str, Output), &'a str>;

trait Parser<'a, Output> {
    fn parse(&self, input: &'a str) -> ParseResult<'a, Output>;

    fn map<B, F>(self, op: F) -> impl Parser<'a, B>
    where
        Self: Sized,
        F: Fn(Output) -> B,
    {
        move |input| {
            let (remaining, output) = self.parse(input)?;
            Ok((remaining, op(output)))
        }
    }

    fn pred<F>(self, f: F) -> impl Parser<'a, Output>
    where
        Self: Sized,
        F: Fn(&Output) -> bool,
    {
        move |input| {
            self.parse(input).and_then(|(remaining, output)| {
                if f(&output) {
                    Ok((remaining, output))
                } else {
                    Err(input)
                }
            })
        }
    }

    fn zero_or_more(self) -> impl Parser<'a, Vec<Output>>
    where
        Self: Sized,
    {
        move |mut input| {
            let mut result = Vec::new();

            while let Ok((next_input, output)) = self.parse(input) {
                result.push(output);
                input = next_input;
            }

            Ok((input, result))
        }
    }

    fn one_or_more(self) -> impl Parser<'a, Vec<Output>>
    where
        Self: Sized,
    {
        move |mut input| {
            let mut result = Vec::new();

            if let Ok((next_input, first_output)) = self.parse(input) {
                result.push(first_output);
                input = next_input;
            } else {
                return Err(input);
            }

            while let Ok((next_input, output)) = self.parse(input) {
                result.push(output);
                input = next_input;
            }

            Ok((input, result))
        }
    }
}

impl<'a, F, Output> Parser<'a, Output> for F
where
    F: Fn(&'a str) -> ParseResult<'a, Output>,
{
    fn parse(&self, input: &'a str) -> ParseResult<'a, Output> {
        self(input)
    }
}

fn match_literal<'a, 'b>(expected: &'a str) -> impl Parser<'b, ()> {
    move |input: &'b str| match input.split_at_checked(expected.len()) {
        Some((first, remaining)) if first == expected => Ok((remaining, ())),
        _ => Err(input),
    }
}

fn identifier(input: &str) -> ParseResult<'_, String> {
    let mut matched = String::new();
    let mut chars = input.chars();

    match chars.next() {
        Some(ch) if ch.is_alphabetic() => matched.push(ch),
        _ => return Err(input),
    }

    for ch in chars {
        if ch.is_alphanumeric() || ch == '-' {
            matched.push(ch);
        } else {
            break;
        }
    }

    Ok((&input[matched.len()..], matched))
}

fn pair<'a, P1, P2, O1, O2>(parser1: P1, parser2: P2) -> impl Parser<'a, (O1, O2)>
where
    P1: Parser<'a, O1>,
    P2: Parser<'a, O2>,
{
    move |input| {
        let (next_input, o1) = parser1.parse(input)?;
        let (remaining, o2) = parser2.parse(next_input)?;
        Ok((remaining, (o1, o2)))
    }
}

fn left<'a, P1, P2, O1, O2>(parser1: P1, parser2: P2) -> impl Parser<'a, O1>
where
    P1: Parser<'a, O1>,
    P2: Parser<'a, O2>,
{
    pair(parser1, parser2).map(|(o1, _o2)| o1)
}

fn right<'a, P1, P2, O1, O2>(parser1: P1, parser2: P2) -> impl Parser<'a, O2>
where
    P1: Parser<'a, O1>,
    P2: Parser<'a, O2>,
{
    pair(parser1, parser2).map(|(_o1, o2)| o2)
}

fn any_char(input: &str) -> ParseResult<'_, char> {
    match input.chars().next() {
        Some(ch) => Ok((&input[ch.len_utf8()..], ch)),
        None => Err(input),
    }
}

fn whitespace_char<'a>() -> impl Parser<'a, char> {
    any_char.pred(|c| c.is_whitespace())
}

fn space1<'a>() -> impl Parser<'a, Vec<char>> {
    whitespace_char().one_or_more()
}

fn space0<'a>() -> impl Parser<'a, Vec<char>> {
    whitespace_char().zero_or_more()
}

fn quoted_string<'a>() -> impl Parser<'a, String> {
    right(
        match_literal("\""),
        left(
            any_char.pred(|c| *c != '"').zero_or_more(),
            match_literal("\""),
        ),
    )
    .map(|chars| chars.into_iter().collect())
}

fn attribute_pair<'a>() -> impl Parser<'a, (String, String)> {
    pair(identifier, right(match_literal("="), quoted_string()))
}

fn attributes<'a>() -> impl Parser<'a, Vec<(String, String)>> {
    right(space1(), attribute_pair()).zero_or_more()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_literal() {
        let parse_joe = match_literal("Hello Joe!");
        assert_eq!(Ok(("", ())), parse_joe.parse("Hello Joe!"));
        assert_eq!(
            Ok((" Hello Robert!", ())),
            parse_joe.parse("Hello Joe! Hello Robert!")
        );
        assert_eq!(Err("Hello Mike!"), parse_joe.parse("Hello Mike!"));
    }

    #[test]
    fn test_identifier() {
        assert_eq!(
            Ok(("", "i-am-an-identifier".to_string())),
            identifier("i-am-an-identifier")
        );
        assert_eq!(
            Ok((" entirely an identifier", "not".to_string())),
            identifier("not entirely an identifier")
        );
        assert_eq!(
            Err("!not at all an identifier"),
            identifier("!not at all an identifier")
        );
    }

    #[test]
    fn test_pair() {
        let tag_opener = pair(match_literal("<"), identifier);
        assert_eq!(
            Ok(("/>", ((), "my-first-element".to_string()))),
            tag_opener.parse("<my-first-element/>")
        );
        assert_eq!(Err("oops"), tag_opener.parse("oops"));
        assert_eq!(Err("!oops"), tag_opener.parse("<!oops"));
    }

    #[test]
    fn test_right() {
        let tag_opener = right(match_literal("<"), identifier);
        assert_eq!(
            Ok(("/>", "my-first-element".to_string())),
            tag_opener.parse("<my-first-element/>")
        );
        assert_eq!(Err("oops"), tag_opener.parse("oops"));
        assert_eq!(Err("!oops"), tag_opener.parse("<!oops"));
    }

    #[test]
    fn test_one_or_more() {
        let parser = match_literal("ha").one_or_more();
        assert_eq!(Ok(("", vec![(), (), ()])), parser.parse("hahaha"));
        assert_eq!(Err("ahah"), parser.parse("ahah"));
        assert_eq!(Err(""), parser.parse(""));
    }

    #[test]
    fn test_zero_or_more() {
        let parser = match_literal("ha").zero_or_more();
        assert_eq!(Ok(("", vec![(), (), ()])), parser.parse("hahaha"));
        assert_eq!(Ok(("ahah", vec![])), parser.parse("ahah"));
        assert_eq!(Ok(("", vec![])), parser.parse(""));
    }

    #[test]
    fn test_predicate() {
        let parser = any_char.pred(|c| *c == 'o');
        assert_eq!(Ok(("mg", 'o')), parser.parse("omg"));
        assert_eq!(Err("lol"), parser.parse("lol"));
    }

    #[test]
    fn test_quoted_string() {
        assert_eq!(
            Ok(("", "Hello Joe!".to_string())),
            quoted_string().parse("\"Hello Joe!\"")
        );
    }

    #[test]
    fn test_attribute() {
        assert_eq!(
            Ok((
                "",
                vec![
                    ("one".to_string(), "1".to_string()),
                    ("two".to_string(), "2".to_string())
                ]
            )),
            attributes().parse(" one=\"1\" two=\"2\"")
        );
    }
}
