use nostr::prelude::Kind;

// Filter for kinds (event types): all or some specific values
pub(crate) struct KindFilter {
    // The 'all' filter
    is_all: bool,
    // Specific kinds
    events: Vec<Kind>,
}

impl KindFilter {
    // The 'all' filter
    pub fn new_all() -> Self {
        KindFilter {
            is_all: true,
            events: Vec::new(),
        }
    }

    // Filter with no kind, more should be added later
    pub fn new_some(kinds: &Vec<Kind>) -> Self {
        let mut f = KindFilter {
            is_all: false,
            events: Vec::new(),
        };
        f.add_vec(kinds);
        f
    }

    pub fn contains(&self, kind: &Kind) -> bool {
        if self.is_all { return true; }
        self.events.iter().find(|&e| e == kind).is_some()
    }

    pub fn add(&mut self, kind: &Kind) {
        if self.is_all { return; }
        if !self.contains(kind) {
            self.events.push(kind.clone());
            self.events.sort();
        }
    }

    pub fn add_vec(&mut self, kinds: &Vec<Kind>) {
        if self.is_all { return; }
        for k in kinds {
            if !self.contains(k) {
                self.events.push(k.clone());
            }
        }
        self.events.sort();
    }

    pub fn from_str(_s: &str) -> Self {
        // TOD parse
        Self::new_all()
    }

    fn format_member(start: u64, end: Option<u64>) -> String {
        if end.is_none() || start == end.unwrap() {
            start.to_string()
        } else {
            format!("{}-{}", start, end.unwrap())
        }
    }

    pub fn to_string(&self) -> String {
        if self.is_all { return "".to_string(); }
        if self.events.len() == 0 {
            // filter for nothing, invalid, return unsatisfiable condition
            return "k=0&k=1".to_string();
        }
        let mut s = Vec::new();
        let mut numbers: Vec<u64> = self.events.iter().map(|&e| e.as_u64()).collect();
        numbers.sort();
        let mut current_start: Option<u64> = None;
        let mut current_end: Option<u64> = None;
        for e in numbers {
            if current_end.is_some() && (current_end.unwrap() + 1) != e {
                s.push(Self::format_member(current_start.unwrap(), current_end));
                current_start = None;
            }
            if current_start.is_none() {
                current_start = Some(e);
            }
            current_end = Some(e);
        }
        if current_start.is_some() && current_end.is_some() {
            s.push(Self::format_member(current_start.unwrap(), current_end));
        }
        "k=".to_string() + &s.join(",")
    }
}

#[cfg(test)]
mod test {
    use super::*;
 
    #[test]
    fn test_new_all() {
        let mut e = KindFilter::new_all();
        assert_eq!(e.to_string(), "");
        e.add(&Kind::TextNote);
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn test_new_some() {
        let e = KindFilter::new_some(&vec![Kind::TextNote, Kind::ContactList]);
        assert_eq!(e.to_string(), "k=1,3");
    }

    #[test]
    fn test_new_some_add() {
        let mut e = KindFilter::new_some(&Vec::new());
        assert_eq!(e.to_string(), "k=0&k=1");
        e.add(&Kind::TextNote);
        assert_eq!(e.to_string(), "k=1");
        e.add(&Kind::ChannelMessage);
        assert_eq!(e.to_string(), "k=1,42");
        e.add(&Kind::Metadata);
        assert_eq!(e.to_string(), "k=0-1,42");
        e.add(&Kind::ContactList);
        assert_eq!(e.to_string(), "k=0-1,3,42");
        e.add(&Kind::RecommendRelay);
        assert_eq!(e.to_string(), "k=0-3,42");
        e.add(&Kind::ChannelMetadata);
        assert_eq!(e.to_string(), "k=0-3,41-42");
        e.add(&Kind::Custom(666));
        e.add(&Kind::Custom(667));
        e.add(&Kind::Custom(668));
        assert_eq!(e.to_string(), "k=0-3,41-42,666-668");
    }

    #[test]
    fn test_from_string() {
        assert_eq!(KindFilter::from_str("").to_string(), "");
        // TODO parse tests
    }
}
