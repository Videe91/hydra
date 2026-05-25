//! # Pagination v0 — shared cursor pagination helper
//!
//! Every list endpoint that wants to be safe under non-trivial data
//! sizes uses this module. The contract is intentionally boring so
//! clients (Python SDK, TS SDK, curl scripts) can implement one walk
//! loop and have it work everywhere:
//!
//! ```text
//! GET /query/<list>?limit=N&after=<cursor>
//! ```
//!
//! Response:
//!
//! ```json
//! { "items": [...], "next_cursor": "id_or_null" }
//! ```
//!
//! v0 rules:
//! - cursor is the stable ID string of the last item returned
//! - default limit is 100, max is 500
//! - unknown `after` cursor returns 400 (not a silent empty page —
//!   that would mask client bugs)
//!
//! The `/events` and `/commits` audit routes had pagination before
//! this patch and keep their existing DTO shapes; they use
//! [`normalized_limit`] here so the limit policy stays uniform across
//! the API.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 500;

/// Clamp a client-requested limit into the v0 policy window
/// (`[1, MAX_LIMIT]`, default `DEFAULT_LIMIT`).
pub fn normalized_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

/// Sentinel returned when the `after` cursor isn't found in the input
/// slice. Callers translate this into HTTP 400.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCursor;

/// Paginate a slice using an ID cursor extractor.
///
/// - `after = None` → start from the beginning
/// - `after = Some(id)` → start from the item just after the one whose
///   cursor equals `id`. Errors if no such item exists.
/// - `next_cursor` is `Some(last_id)` when there is more data after
///   this page, `None` when this was the final page.
pub fn paginate_by_cursor<T, F>(
    items: &[T],
    after: Option<&str>,
    limit: Option<usize>,
    cursor_for: F,
) -> Result<Page<T>, UnknownCursor>
where
    T: Clone,
    F: Fn(&T) -> String,
{
    let mut start_index = 0;
    if let Some(after) = after {
        match items.iter().position(|item| cursor_for(item) == after) {
            Some(index) => start_index = index + 1,
            None => return Err(UnknownCursor),
        }
    }
    let limit = normalized_limit(limit);
    let page_items: Vec<T> = items
        .iter()
        .skip(start_index)
        .take(limit)
        .cloned()
        .collect();
    let next_cursor = if start_index + page_items.len() < items.len() {
        page_items.last().map(&cursor_for)
    } else {
        None
    };
    Ok(Page {
        items: page_items,
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Item {
        id: String,
    }

    fn items(count: usize) -> Vec<Item> {
        (0..count)
            .map(|index| Item {
                id: format!("item_{index}"),
            })
            .collect()
    }

    #[test]
    fn paginates_first_page() {
        let items = items(3);
        let page = paginate_by_cursor(&items, None, Some(2), |item| item.id.clone()).unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].id, "item_0");
        assert_eq!(page.items[1].id, "item_1");
        assert_eq!(page.next_cursor, Some("item_1".to_string()));
    }

    #[test]
    fn paginates_after_cursor() {
        let items = items(4);
        let page = paginate_by_cursor(&items, Some("item_1"), Some(2), |item| item.id.clone())
            .unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].id, "item_2");
        assert_eq!(page.items[1].id, "item_3");
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn unknown_cursor_errors() {
        let items = items(2);
        let result = paginate_by_cursor(&items, Some("missing"), Some(1), |item| item.id.clone());
        assert!(result.is_err());
    }

    #[test]
    fn clamps_limit() {
        let items = items(600);
        let page =
            paginate_by_cursor(&items, None, Some(999), |item| item.id.clone()).unwrap();
        assert_eq!(page.items.len(), MAX_LIMIT);
        assert_eq!(page.next_cursor, Some("item_499".to_string()));
    }

    #[test]
    fn empty_input_returns_empty_page() {
        let items: Vec<Item> = vec![];
        let page = paginate_by_cursor(&items, None, Some(10), |item| item.id.clone()).unwrap();
        assert_eq!(page.items.len(), 0);
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn default_limit_used_when_unspecified() {
        let items = items(DEFAULT_LIMIT + 5);
        let page = paginate_by_cursor(&items, None, None, |item| item.id.clone()).unwrap();
        assert_eq!(page.items.len(), DEFAULT_LIMIT);
        assert_eq!(
            page.next_cursor,
            Some(format!("item_{}", DEFAULT_LIMIT - 1))
        );
    }

    #[test]
    fn normalized_limit_defaults_and_clamps() {
        assert_eq!(normalized_limit(None), DEFAULT_LIMIT);
        assert_eq!(normalized_limit(Some(42)), 42);
        assert_eq!(normalized_limit(Some(MAX_LIMIT + 1)), MAX_LIMIT);
    }
}
