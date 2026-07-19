//! Intrusive doubly-linked list.
//!
//! [`IntrusiveLinkedList<T>`] is a doubly-linked list that does **not** own
//! its elements. Instead, each element carries its own prev/next link storage
//! by implementing the [`Links`] trait, and the list threads those links
//! together. This is the classic no-allocation linked list used everywhere in
//! a kernel:
//!
//! * scheduler run queues (a task struct is a list node — no `Box<Task>`);
//! * the slabs of the kernel heap (free blocks link themselves together);
//! * timer wheel entries; wait queues; per-CPU deferred-work lists.
//!
//! # Why intrusive?
//!
//! A normal `alloc::collections::LinkedList<T>` heap-allocates a node for every
//! `push`. In ring 0, before the heap exists — and even after it exists, for
//! hot paths that cannot afford the allocation — that is unacceptable. An
//! intrusive list pays zero allocation cost: the element already exists (it is
//! a stack frame, a `static`, a slab slot), and the list merely borrows it.
//!
//! # The `Links` contract
//!
//! An element type `T` implements `Links` by exposing a `&mut LinkEntry<T>`.
//! The link entry holds two `Option<NonNull<T>>` pointers (`prev`, `next`).
//! The list reads and writes these through the trait; it never touches the
//! element's other fields. A single `T` may participate in several lists at
//! once by carrying several `LinkEntry`s and implementing `Links` once per
//! list (via a newtype wrapper or by naming the entry in the trait impl).
//!
//! # Safety
//!
//! Every method that touches `prev`/`next` is `unsafe` at the trait boundary
//! and wrapped in a safe API on `IntrusiveLinkedList` that upholds three
//! invariants:
//!
//! 1. **Liveness**: a node inserted into a list must outlive its membership.
//!    The caller pins the element (e.g. in a `static` or a slab slot) for the
//!    duration; the list holds `NonNull<T>` raw pointers but never owns the
//!    memory.
//! 2. **Uniqueness of membership**: a given `LinkEntry` may belong to at most
//!    one list at a time. Re-inserting an already-linked node corrupts both
//!    lists. The `push_*` methods assert that the node is unlinked (`prev` and
//!    `next` are both `None`) before linking it, catching this class of bug.
//! 3. **No aliasing of `&mut T`**: the list never hands out `&mut T` to a node
//!    while that node is linked — only `&T` via the iterator. Removing a node
//!    returns the raw pointer so the caller can resume exclusive access.
//!
//! Because the list holds raw pointers, the borrow checker cannot enforce
//! these invariants; the `unsafe` blocks below document which invariant each
//! operation relies on.

use core::marker::PhantomData;
use core::ptr::NonNull;

/// The link storage an element carries to participate in an
/// [`IntrusiveLinkedList`].
///
/// `prev`/`next` are `None` at the ends of a non-empty list (`prev == None` on
/// the head, `next == None` on the tail). The [`in_list`](Self::in_list) flag
/// is the authoritative membership marker: it is `true` iff the node is
/// currently linked into some list. The flag exists because a sole node — the
/// only element of a single-element list — has both `prev` and `next` equal
/// to `None`, which would otherwise be indistinguishable from an unlinked
/// node. Tracking membership with an explicit boolean keeps the
/// [`is_unlinked`](Self::is_unlinked) check sound in every configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkEntry<T> {
    /// Pointer to the predecessor, or `None` if this is the list head.
    pub prev: Option<NonNull<T>>,
    /// Pointer to the successor, or `None` if this is the list tail.
    pub next: Option<NonNull<T>>,
    /// `true` while the node is linked into a list. Set on insert, cleared on
    /// remove. This is the membership marker that disambiguates the sole-node
    /// case from the unlinked case.
    in_list: bool,
}

impl<T> LinkEntry<T> {
    /// A fresh, unlinked entry: both pointers `None` and `in_list = false`.
    ///
    /// Elements should initialise their link storage with this in their
    /// constructor so that the "unlinked" precondition of `push_*` holds.
    #[inline]
    pub const fn new() -> Self {
        LinkEntry {
            prev: None,
            next: None,
            in_list: false,
        }
    }

    /// `true` if the entry is not currently linked into any list.
    ///
    /// This is the precondition every `push_*` method checks. It consults the
    /// [`in_list`](Self::in_list) flag rather than the pointer pair, so it
    /// stays correct for a sole node (whose `prev` and `next` are both
    /// `None` while it is linked).
    #[inline]
    pub const fn is_unlinked(&self) -> bool {
        !self.in_list
    }

    /// `true` if the entry is currently linked into a list.
    #[inline]
    pub const fn is_linked(&self) -> bool {
        self.in_list
    }
}

/// Trait by which [`IntrusiveLinkedList`] accesses an element's link storage.
///
/// Implementing this trait is the element's declaration that it carries a
/// `LinkEntry<Self>` field and is willing to let the list mutate it. The list
/// never touches any other field of `T`.
///
/// The `Sized` supertrait is required because `LinkEntry<T>` stores `T`'s link
/// pointers by value and the list manipulates elements through concrete
/// `NonNull<T>` references; an unsized `T` has no fixed layout to thread links
/// through. Every realistic intrusive-list element (task, slab block, timer
/// entry) is `Sized`, so this is not a practical restriction.
///
/// # Example
///
/// ```
/// use xenith_kernel::util::linked_list::{IntrusiveLinkedList, LinkEntry, Links};
/// use core::ptr::NonNull;
///
/// struct Task {
///     name: &'static str,
///     links: LinkEntry<Task>,
/// }
///
/// impl Links for Task {
///     fn links(&self) -> &LinkEntry<Task> { &self.links }
///     fn links_mut(&mut self) -> &mut LinkEntry<Task> { &mut self.links }
/// }
/// ```
pub trait Links: Sized {
    /// Shared access to this element's link entry.
    fn links(&self) -> &LinkEntry<Self>;

    /// Exclusive access to this element's link entry.
    ///
    /// The list uses this to update `prev`/`next` during insert and remove.
    fn links_mut(&mut self) -> &mut LinkEntry<Self>;
}

/// An intrusive doubly-linked list of `T`.
///
/// See the [module documentation](crate::util::linked_list) for the safety
/// contract every caller must uphold.
#[derive(Debug)]
pub struct IntrusiveLinkedList<T: Links> {
    /// Pointer to the first element, or `None` if the list is empty.
    head: Option<NonNull<T>>,
    /// Pointer to the last element, or `None` if the list is empty.
    tail: Option<NonNull<T>>,
    /// Cached element count. Maintained on every insert/remove so `len()` is
    /// O(1) — the scheduler queries this on every tick to decide preemption.
    len: usize,
    /// `T` is only used through raw pointers in the links; the `PhantomData`
    /// keeps the lifetime relationship visible to the borrow checker without
    /// implying ownership.
    _marker: PhantomData<T>,
}

// SAFETY: `IntrusiveLinkedList` does not own its elements and does not share
// `Send`-ability with them implicitly. Sending the list handle to another
// thread is sound only if the elements themselves can be accessed from that
// thread, which is the caller's responsibility. We forward `Send` iff `T:
// Send` to keep the common case (linked `Send` nodes) ergonomic while
// preventing the rarer `!Send` case from silently crossing a thread boundary.
unsafe impl<T: Links + Send> Send for IntrusiveLinkedList<T> {}
// `Sync` is intentionally NOT implemented: concurrent access to the list head
// is the caller's job (wrap it in a `crate::sync` lock). Auto-impl would imply
// `&List` is safe to share, which it is not without external synchronisation.

impl<T: Links> IntrusiveLinkedList<T> {
    /// Construct an empty list.
    #[inline]
    pub const fn new() -> Self {
        IntrusiveLinkedList {
            head: None,
            tail: None,
            len: 0,
            _marker: PhantomData,
        }
    }

    /// Number of elements currently in the list.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` if the list holds no elements.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Pointer to the first element, or `None` if empty.
    ///
    /// Exposed for callers that need to peek at the head without popping (the
    /// scheduler's "next task to run" query). The pointer is valid for as long
    /// as the element remains linked and the caller's liveness guarantee
    /// holds.
    #[inline]
    pub fn head(&self) -> Option<NonNull<T>> {
        self.head
    }

    /// Pointer to the last element, or `None` if empty.
    #[inline]
    pub fn tail(&self) -> Option<NonNull<T>> {
        self.tail
    }

    // --- Link access helpers -----------------------------------------------

    /// Read the `next` pointer of a linked node.
    ///
    /// # Safety
    ///
    /// `node` must point to a live `T` that is currently linked into *some*
    /// list (not necessarily this one — but the caller ensures it is this one
    /// for all real call sites). The links field is read shared.
    #[inline]
    unsafe fn next_of(node: NonNull<T>) -> Option<NonNull<T>> {
        // SAFETY: caller guarantees `node` is a live, linked `T`. We take a
        // shared reference to read the `next` field; no mutation occurs.
        let t = unsafe { node.as_ref() };
        t.links().next
    }

    /// Read the `prev` pointer of a linked node.
    ///
    /// # Safety
    ///
    /// Same contract as [`next_of`](Self::next_of).
    #[inline]
    unsafe fn prev_of(node: NonNull<T>) -> Option<NonNull<T>> {
        // SAFETY: caller guarantees `node` is a live, linked `T`. Shared read
        // of the `prev` field.
        let t = unsafe { node.as_ref() };
        t.links().prev
    }

    /// Write the `prev` pointer of a linked node.
    ///
    /// # Safety
    ///
    /// `node` must point to a live `T`. The caller must ensure no other
    /// `&mut T` to this node is outstanding (aliasing rule).
    #[inline]
    unsafe fn set_prev(mut node: NonNull<T>, prev: Option<NonNull<T>>) {
        // SAFETY: caller guarantees `node` is live and unaliased. We obtain
        // `&mut T` solely to update the link entry, which is the contract
        // `Links` grants the list. `node` is declared `mut` because
        // `NonNull::as_mut` borrows the `NonNull` itself by `&mut`.
        let t = unsafe { node.as_mut() };
        t.links_mut().prev = prev;
    }

    /// Write the `next` pointer of a linked node.
    ///
    /// # Safety
    ///
    /// Same contract as [`set_prev`](Self::set_prev).
    #[inline]
    unsafe fn set_next(mut node: NonNull<T>, next: Option<NonNull<T>>) {
        // SAFETY: caller guarantees `node` is live and unaliased.
        let t = unsafe { node.as_mut() };
        t.links_mut().next = next;
    }

    /// Set the `in_list` flag on a node.
    ///
    /// # Safety
    ///
    /// `node` must point to a live `T` and the caller must hold exclusive
    /// access to its links.
    #[inline]
    unsafe fn set_linked(mut node: NonNull<T>, linked: bool) {
        // SAFETY: caller guarantees `node` is live and unaliased for link
        // mutation. Only the private `in_list` field is touched.
        let t = unsafe { node.as_mut() };
        t.links_mut().in_list = linked;
    }

    // --- Insertion ---------------------------------------------------------

    /// Insert `node` at the front of the list.
    ///
    /// After this call `node` is the head. The element must currently be
    /// unlinked (its `LinkEntry` must have both pointers `None`); re-inserting
    /// a linked node is a programming error and panics.
    ///
    /// # Safety
    ///
    /// The caller guarantees that `node` points to a live `T` that will
    /// outlive its membership in this list, and that no other code holds a
    /// `&mut T` to `node` while it is linked.
    #[inline]
    pub fn push_front(&mut self, node: NonNull<T>) {
        // SAFETY: the link state is inspected to assert the node is unlinked.
        // We take a shared reference to the links to check, which is sound for
        // any live `T`.
        let unlinked = unsafe { node.as_ref() }.links().is_unlinked();
        assert!(
            unlinked,
            "linked_list: push_front on an already-linked node"
        );

        // SAFETY: `node` is live and, per the assertion above, unaliased for
        // mutation of its links. We set `prev = None` (it will be the new
        // head) and `next = old head`.
        unsafe {
            Self::set_prev(node, None);
            Self::set_next(node, self.head);
        }
        match self.head {
            // The list was non-empty: the old head's `prev` becomes `node`.
            Some(old_head) => {
                // SAFETY: `old_head` is live (it was in the list) and we hold
                // `&mut self`, which is the only path that mutates links.
                unsafe {
                    Self::set_prev(old_head, Some(node));
                }
            },
            // The list was empty: `node` also becomes the tail.
            None => self.tail = Some(node),
        }
        self.head = Some(node);
        // SAFETY: mark the node as linked so a subsequent re-insert attempt is
        // rejected by the `is_unlinked` precondition.
        unsafe {
            Self::set_linked(node, true);
        }
        self.len += 1;
    }

    /// Append `node` to the back of the list.
    ///
    /// After this call `node` is the tail. Same preconditions and safety
    /// contract as [`push_front`](Self::push_front).
    #[inline]
    pub fn push_back(&mut self, node: NonNull<T>) {
        let unlinked = unsafe { node.as_ref() }.links().is_unlinked();
        assert!(unlinked, "linked_list: push_back on an already-linked node");

        // SAFETY: `node` is live and unaliased for link mutation. `prev =
        // old tail`, `next = None` (new tail).
        unsafe {
            Self::set_prev(node, self.tail);
            Self::set_next(node, None);
        }
        match self.tail {
            Some(old_tail) => {
                // SAFETY: `old_tail` is live and only this list mutates its
                // links via `&mut self`.
                unsafe {
                    Self::set_next(old_tail, Some(node));
                }
            },
            None => self.head = Some(node),
        }
        self.tail = Some(node);
        // SAFETY: mark the node as linked.
        unsafe {
            Self::set_linked(node, true);
        }
        self.len += 1;
    }

    // --- Removal -----------------------------------------------------------

    /// Remove and return the first element, or `None` if the list is empty.
    ///
    /// The returned pointer is no longer linked into any list and its
    /// `LinkEntry` has been reset to the unlinked state. The caller resumes
    /// full ownership.
    #[inline]
    pub fn pop_front(&mut self) -> Option<NonNull<T>> {
        let head = self.head?;
        // SAFETY: `head` is live and currently the list head. We unlink it
        // through `remove_internal`, which fixes up the successor and the
        // list's `head`/`tail` pointers atomically with respect to `&mut self`.
        unsafe {
            self.remove_internal(head);
        }
        Some(head)
    }

    /// Remove and return the last element, or `None` if the list is empty.
    #[inline]
    pub fn pop_back(&mut self) -> Option<NonNull<T>> {
        let tail = self.tail?;
        unsafe {
            self.remove_internal(tail);
        }
        Some(tail)
    }

    /// Remove `node` from the list.
    ///
    /// `node` must be currently linked into **this** list. Removing a node
    /// that belongs to a different list corrupts that list. After this call
    /// the node's `LinkEntry` is reset to the unlinked state.
    ///
    /// # Safety
    ///
    /// In addition to the global liveness obligation, the caller must ensure
    /// `node` is a member of this list. The list cannot check this itself.
    #[inline]
    pub unsafe fn remove(&mut self, node: NonNull<T>) {
        // SAFETY: caller asserts `node` is linked into this list.
        unsafe {
            self.remove_internal(node);
        }
    }

    /// Internal unlink routine. Fixes up the neighbours and the list
    /// head/tail, then resets the node's link entry.
    ///
    /// # Safety
    ///
    /// `node` must be live and currently linked into this list.
    #[inline]
    unsafe fn remove_internal(&mut self, node: NonNull<T>) {
        let prev = unsafe { Self::prev_of(node) };
        let next = unsafe { Self::next_of(node) };

        // Splice the predecessor's `next` to skip `node`.
        match prev {
            Some(p) => unsafe {
                Self::set_next(p, next);
            },
            None => self.head = next, // `node` was the head
        }
        // Splice the successor's `prev` to skip `node`.
        match next {
            Some(n) => unsafe {
                Self::set_prev(n, prev);
            },
            None => self.tail = prev, // `node` was the tail
        }

        // Reset the removed node's links to the unlinked state so it can be
        // safely re-inserted later and so `is_unlinked()` reports `true`.
        // SAFETY: `node` is live; we hold the only path that mutates its
        // links (`&mut self`). Clearing the pointers and the `in_list` flag
        // together restores the `LinkEntry::new()` state.
        unsafe {
            Self::set_prev(node, None);
            Self::set_next(node, None);
            Self::set_linked(node, false);
        }
        self.len -= 1;
    }

    // --- Iteration ---------------------------------------------------------

    /// Borrowing iterator over the list elements, head to tail.
    ///
    /// The iterator yields `&T` references whose lifetime is tied to `&self`,
    /// so it is safe even though the list stores raw pointers: no `&mut self`
    /// method (which could unlink a node) can run while the iterator is live.
    #[inline]
    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            next: self.head,
            _marker: PhantomData,
        }
    }
}

impl<T: Links> Default for IntrusiveLinkedList<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowing iterator over an [`IntrusiveLinkedList`].
///
/// See [`IntrusiveLinkedList::iter`]. The iterator is `Clone` so a caller can
/// snapshot a position and resume from it later.
#[derive(Clone)]
pub struct Iter<'a, T: Links> {
    /// Pointer to the next node to yield, or `None` when exhausted.
    next: Option<NonNull<T>>,
    _marker: PhantomData<&'a T>,
}

impl<'a, T: Links> Iterator for Iter<'a, T> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<&'a T> {
        let cur = self.next?;
        // SAFETY: `cur` points to a live `T` that remains linked for as long
        // as `&self` is borrowed (the iterator's lifetime is tied to the
        // list's shared borrow, which excludes mutating methods). We take a
        // shared reference and advance to the stored `next`.
        let t = unsafe { cur.as_ref() };
        self.next = t.links().next;
        // SAFETY: the shared reference's lifetime is constrained to `'a`, the
        // lifetime of the list's shared borrow, so it cannot outlive the
        // element's membership.
        Some(unsafe { &*cur.as_ptr() })
    }
}

// SAFETY: `Iter` is a read-only cursor. Forwarding `Send`/`Sync` iff `T` is
// `Send`/`Sync` matches the shared-reference semantics the iterator exposes.
unsafe impl<'a, T: Links + Sync> Sync for Iter<'a, T> {}
unsafe impl<'a, T: Links + Send> Send for Iter<'a, T> {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A test element: a payload plus the link storage it needs to participate
    /// in a list. `Drop` is not required for the link logic, but we leave it
    /// out deliberately: the list never owns its elements, so nothing here
    /// should implicitly drop.
    struct Node {
        value: u32,
        links: LinkEntry<Node>,
    }

    impl Node {
        fn new(value: u32) -> Self {
            Node {
                value,
                links: LinkEntry::new(),
            }
        }

        /// Convenience to build a `NonNull` from a stack-owned owner. In test
        /// code we keep `Node`s on the stack and pin them by reference for the
        /// duration of the test, which is the liveness contract the list
        /// requires.
        fn ptr(node: &mut Node) -> NonNull<Node> {
            // SAFETY: `node` is a live, non-null reference for the duration of
            // the test. The caller (each test) keeps the `Node` alive while it
            // is linked.
            unsafe { NonNull::new_unchecked(node as *mut Node) }
        }
    }

    impl Links for Node {
        fn links(&self) -> &LinkEntry<Node> {
            &self.links
        }
        fn links_mut(&mut self) -> &mut LinkEntry<Node> {
            &mut self.links
        }
    }

    /// Collect the `value` field of every node in `list` into a stack buffer.
    ///
    /// `Vec` is not available (no allocator in the kernel crate), so the test
    /// harness writes into a fixed array and returns the populated slice. The
    /// buffer is generous enough for every test in this module.
    fn collect_values(list: &IntrusiveLinkedList<Node>) -> [u32; 8] {
        let mut out = [0u32; 8];
        for (i, n) in list.iter().enumerate() {
            assert!(i < out.len(), "test buffer overflow; raise the cap");
            out[i] = n.value;
        }
        out
    }

    #[test]
    fn new_is_empty() {
        let list: IntrusiveLinkedList<Node> = IntrusiveLinkedList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(list.head().is_none());
        assert!(list.tail().is_none());
    }

    #[test]
    fn push_front_orders_head_to_tail() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        list.push_front(Node::ptr(&mut a));
        list.push_front(Node::ptr(&mut b));
        list.push_front(Node::ptr(&mut c));

        assert_eq!(list.len(), 3);
        // push_front => head is c, then b, then a.
        assert_eq!(&collect_values(&list)[..3], [3, 2, 1]);
    }

    #[test]
    fn push_back_orders_head_to_tail() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        list.push_back(Node::ptr(&mut a));
        list.push_back(Node::ptr(&mut b));
        list.push_back(Node::ptr(&mut c));

        assert_eq!(list.len(), 3);
        assert_eq!(&collect_values(&list)[..3], [1, 2, 3]);
    }

    #[test]
    fn pop_front_returns_in_order() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(10);
        let mut b = Node::new(20);

        list.push_back(Node::ptr(&mut a));
        list.push_back(Node::ptr(&mut b));

        let first = list.pop_front().unwrap();
        // SAFETY: `first` is a live pointer to `a`, which is still on the test
        // stack. We only read a field.
        assert_eq!(unsafe { first.as_ref() }.value, 10);
        assert_eq!(list.len(), 1);
        // The popped node's links must be reset to unlinked.
        assert!(a.links.is_unlinked());

        let second = list.pop_front().unwrap();
        assert_eq!(unsafe { second.as_ref() }.value, 20);
        assert!(list.is_empty());
        assert!(list.pop_front().is_none());
    }

    #[test]
    fn pop_back_returns_in_reverse_order() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        list.push_back(Node::ptr(&mut a));
        list.push_back(Node::ptr(&mut b));
        list.push_back(Node::ptr(&mut c));

        assert_eq!(unsafe { list.pop_back().unwrap().as_ref() }.value, 3);
        assert_eq!(unsafe { list.pop_back().unwrap().as_ref() }.value, 2);
        assert_eq!(unsafe { list.pop_back().unwrap().as_ref() }.value, 1);
        assert!(list.is_empty());
    }

    #[test]
    fn remove_middle_splices_neighbours() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        list.push_back(Node::ptr(&mut a));
        list.push_back(Node::ptr(&mut b));
        list.push_back(Node::ptr(&mut c));

        // Remove the middle node. After this a.next must point to c and
        // c.prev must point to a.
        // SAFETY: `b` is a member of `list`.
        unsafe {
            list.remove(Node::ptr(&mut b));
        }

        assert_eq!(list.len(), 2);
        assert!(b.links.is_unlinked());
        assert_eq!(&collect_values(&list)[..2], [1, 3]);
    }

    #[test]
    fn remove_head_fixes_list_head() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        list.push_back(Node::ptr(&mut a));
        list.push_back(Node::ptr(&mut b));

        // SAFETY: `a` is the head of `list`.
        unsafe {
            list.remove(Node::ptr(&mut a));
        }
        assert_eq!(list.len(), 1);
        assert!(a.links.is_unlinked());
        assert_eq!(unsafe { list.head().unwrap().as_ref() }.value, 2);
        // `b` is now the only node: both its links should be None.
        assert!(b.links.prev.is_none());
        assert!(b.links.next.is_none());
    }

    #[test]
    fn remove_tail_fixes_list_tail() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        list.push_back(Node::ptr(&mut a));
        list.push_back(Node::ptr(&mut b));

        // SAFETY: `b` is the tail of `list`.
        unsafe {
            list.remove(Node::ptr(&mut b));
        }
        assert_eq!(list.len(), 1);
        assert!(b.links.is_unlinked());
        assert_eq!(unsafe { list.tail().unwrap().as_ref() }.value, 1);
        assert!(a.links.prev.is_none());
        assert!(a.links.next.is_none());
    }

    #[test]
    fn remove_only_node_empties_list() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(42);
        list.push_back(Node::ptr(&mut a));
        // SAFETY: `a` is the sole member of `list`.
        unsafe {
            list.remove(Node::ptr(&mut a));
        }
        assert!(list.is_empty());
        assert!(list.head().is_none());
        assert!(list.tail().is_none());
        assert!(a.links.is_unlinked());
    }

    #[test]
    fn iter_visits_all_in_order() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        // Build five nodes in a stack array and push them in order. Each
        // element gets its own `Node::new` initialiser; `[Node::new(0); 5]`
        // would require `Node: Copy`, which it is not.
        let mut storage = [
            Node::new(0),
            Node::new(0),
            Node::new(0),
            Node::new(0),
            Node::new(0),
        ];
        for (i, n) in storage.iter_mut().enumerate() {
            n.value = (i + 1) as u32;
            list.push_back(Node::ptr(n));
        }
        assert_eq!(&collect_values(&list)[..5], [1, 2, 3, 4, 5]);
    }

    #[test]
    fn iter_is_empty_when_list_empty() {
        let list: IntrusiveLinkedList<Node> = IntrusiveLinkedList::new();
        assert_eq!(list.iter().count(), 0);
    }

    #[test]
    fn push_pop_round_trip_preserves_order() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut storage = [Node::new(0), Node::new(0), Node::new(0), Node::new(0)];
        for (i, n) in storage.iter_mut().enumerate() {
            n.value = i as u32;
            list.push_back(Node::ptr(n));
        }
        for i in 0..4 {
            let p = list.pop_front().unwrap();
            assert_eq!(unsafe { p.as_ref() }.value, i as u32);
        }
        assert!(list.is_empty());
    }

    #[test]
    fn reinsert_after_remove() {
        // A node that was removed must be re-insertable: its links were reset
        // to the unlinked state by `remove_internal`.
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        list.push_back(Node::ptr(&mut a));
        list.push_back(Node::ptr(&mut b));
        // SAFETY: `a` is in `list`.
        unsafe {
            list.remove(Node::ptr(&mut a));
        }
        // Re-insert at the back. This must not panic on the "already-linked"
        // assertion because `remove` reset the links.
        list.push_back(Node::ptr(&mut a));
        assert_eq!(&collect_values(&list)[..2], [2, 1]);
    }

    #[test]
    #[should_panic(expected = "already-linked")]
    fn push_front_on_linked_node_panics() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        list.push_back(Node::ptr(&mut a));
        // Inserting the same node again must panic: it is still linked.
        list.push_front(Node::ptr(&mut a));
    }

    #[test]
    #[should_panic(expected = "already-linked")]
    fn push_back_on_linked_node_panics() {
        let mut list = IntrusiveLinkedList::<Node>::new();
        let mut a = Node::new(1);
        list.push_front(Node::ptr(&mut a));
        list.push_back(Node::ptr(&mut a));
    }
}
