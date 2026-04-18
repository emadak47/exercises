#[derive(Debug)]
struct Element {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Element>,
}

type ParseResult<'a, Output> = Result<(&'a str, Output), &'a str>;

trait Parser<'a, Output> {
    fn parse(&self, input: &'a str) -> ParseResult<'a, Output>;
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

fn map<'a, P, F, A, B>(parser: P, map_f: F) -> impl Parser<'a, B>
where
    P: Parser<'a, A>,
    F: Fn(A) -> B,
{
    move |input| {
        let (remaining, output) = parser.parse(input)?;
        Ok((remaining, map_f(output)))
    }
}

fn left<'a, P1, P2, O1, O2>(parser1: P1, parser2: P2) -> impl Parser<'a, O1>
where
    P1: Parser<'a, O1>,
    P2: Parser<'a, O2>,
{
    map(pair(parser1, parser2), |(o1, _o2)| o1)
}

fn right<'a, P1, P2, O1, O2>(parser1: P1, parser2: P2) -> impl Parser<'a, O2>
where
    P1: Parser<'a, O1>,
    P2: Parser<'a, O2>,
{
    map(pair(parser1, parser2), |(_o1, o2)| o2)
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
}
