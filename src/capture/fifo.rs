/// A simple unbounded ringbuffer fifo queue
///
/// The memory footprint will increase when full, but never decrease.
pub struct Fifo<T: Sized + Clone> {
    /// A circular ring buffer, which can grow if full
    buffer: Vec<T>,

    /// The number of items in the queue
    size: usize,

    /// The index used for the next dequeue
    head: usize,

    /// The index for the next enqueue
    tail: usize,
}

impl<T: Sized + Clone> Fifo<T> {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(512),
            size: 0,
            head: 0,
            tail: 0,
        }
    }

    /// Enqueue a new item in the queue
    pub fn enqueue(&mut self, item: T) {
        if self.tail == self.head && self.size > 0 {
            // The vector is full, so we have to re-allocate it to a new one
            let mut old_buffer =
                std::mem::replace(&mut self.buffer, Vec::with_capacity(self.size * 2));
            self.buffer.extend(old_buffer.drain(self.tail..));
            self.buffer.extend(old_buffer.drain(..));

            // Make sure to update the head and tail
            self.head = 0;
            self.size += 1;
            self.tail = self.size;

            // Finally, push the new value
            self.buffer.push(item);
        } else if self.buffer.len() < self.buffer.capacity() {
            // We still have not filled up the vector, so use push
            self.buffer.push(item);
            self.tail = (self.tail + 1) % self.buffer.capacity();
            self.size += 1;
        } else {
            // We have filled up the vector, so now we wrap
            self.buffer[self.tail] = item;
            self.tail = (self.tail + 1) % self.buffer.capacity();
            self.size += 1;
        }
    }

    /// Peek at the first item in the queue
    pub fn peek(&self) -> Option<&T> {
        if self.size > 0 {
            Some(&self.buffer[self.head])
        } else {
            None
        }
    }

    /// Dequeue the oldest item in the queue
    pub fn dequeue(&mut self) -> Option<T> {
        if self.size > 0 {
            let item = self.buffer[self.head].clone();
            self.head = (self.head + 1) % self.buffer.capacity();
            self.size -= 1;
            Some(item)
        } else {
            None
        }
    }
}
