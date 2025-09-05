use candid::{CandidType, Deserialize};
use ic_cdk_macros::*;
use std::cell::RefCell;
use std::collections::VecDeque;

thread_local! {
    static MESSAGE_QUEUE: RefCell<VecDeque<String>> = RefCell::new(VecDeque::new());
}

// Add a message to the queue
#[update]
fn enqueue(message: String) {
    MESSAGE_QUEUE.with(|queue| queue.borrow_mut().push_back(message));
}

// Remove and return the oldest message from the queue
#[update]
fn dequeue() -> Option<String> {
    MESSAGE_QUEUE.with(|queue| queue.borrow_mut().pop_front())
}

// Peek at the next message (do not remove)
#[query]
fn peek() -> Option<String> {
    MESSAGE_QUEUE.with(|queue| queue.borrow().front().cloned())
}

// Return current queue size
#[query]
fn size() -> usize {
    MESSAGE_QUEUE.with(|queue| queue.borrow().len())
}

// Clear the entire queue
#[update]
fn clear() {
    MESSAGE_QUEUE.with(|queue| queue.borrow_mut().clear());
}

pub struct Deq {
    queue: VecDeque<String>,
}

impl Deq {
    pub fn new() -> Self {
        Deq {
            queue: VecDeque::new(),
        }
    }

    pub fn enqueue(&mut self, msg: String) {
        self.queue.push_back(msg);
    }

    pub fn dequeue(&mut self) -> Option<String> {
        self.queue.pop_front()
    }

    pub fn peek(&self) -> Option<&String> {
        self.queue.front()
    }

    pub fn size(&self) -> usize {
        self.queue.len()
    }

    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

pub type Txid = [u8; 32];

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum CtlMsg {
    Hello,
    Track { txid: Txid, depth: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enqueue_dequeue() {
        // Clear queue first
        clear();

        // Enqueue messages
        enqueue("msg1".to_string());
        enqueue("msg2".to_string());

        // Check size
        assert_eq!(size(), 2);

        // Peek at the first message
        assert_eq!(peek(), Some("msg1".to_string()));

        // Dequeue and check messages
        assert_eq!(dequeue(), Some("msg1".to_string()));
        assert_eq!(dequeue(), Some("msg2".to_string()));
        assert_eq!(dequeue(), None); // queue is now empty
    }

    #[test]
    fn test_clear() {
        clear();
        enqueue("msg".to_string());
        assert_eq!(size(), 1);
        clear();
        assert_eq!(size(), 0);
        assert_eq!(peek(), None);
        assert_eq!(dequeue(), None);
    }

    #[test]
    fn test_deq_struct() {
        let mut deq = Deq::new();

        deq.enqueue("msg1".to_string());
        deq.enqueue("msg2".to_string());

        assert_eq!(deq.size(), 2);
        assert_eq!(deq.peek(), Some(&"msg1".to_string()));

        assert_eq!(deq.dequeue(), Some("msg1".to_string()));
        assert_eq!(deq.dequeue(), Some("msg2".to_string()));
        assert_eq!(deq.dequeue(), None);

        deq.enqueue("msg3".to_string());
        deq.clear();
        assert_eq!(deq.size(), 0);
        assert_eq!(deq.peek(), None);
    }
}

#[cfg(test)]
mod message_tests {
    use super::*;
    use base64;
    use base64::{Engine as _, engine::general_purpose};
    use candid::Encode;

    #[test]
    fn test_enqueue_dequeue_ctlmsg() {
        clear(); // clear the queue first

        // Create a sample txid (array of 32 bytes)
        let txid: Txid = [1u8; 32];
        let msg = CtlMsg::Track { txid, depth: 3 };

        // Encode message to candid bytes
        let encoded = Encode!(&msg).expect("Encode failed");
        // Convert bytes to base64 string to store in queue
        let encoded_str = general_purpose::STANDARD.encode(&encoded);

        // Enqueue the encoded string
        enqueue(encoded_str.clone());

        // Check queue size
        assert_eq!(size(), 1);

        // Peek at the message string and verify equality
        assert_eq!(peek().unwrap(), encoded_str);

        // Dequeue and verify the string matches
        let dequeued = dequeue().unwrap();
        assert_eq!(dequeued, encoded_str);
    }
}
