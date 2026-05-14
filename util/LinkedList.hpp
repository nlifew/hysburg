
#ifndef HYSBURG_LINKED_LIST_HPP
#define HYSBURG_LINKED_LIST_HPP

#include <cassert>
#include "Util.hpp"

namespace hysburg {

/**
 * 侵入式双向链表。元素类型 T 须具备 T *mPrev, T *mNext 两个公开（或已授权访问的）指针字段。
 */
template<typename T>
class LinkedList {
    T *mHead = nullptr;
    T *mTail = nullptr;

    // 仅更新相邻节点和头尾指针，不清零 value 自身的 mPrev/mNext
    T *doDetach(T *value) {
        auto prev = value->mPrev;
        auto next = value->mNext;

        if (prev != nullptr) { prev->mNext = next; }
        if (next != nullptr) { next->mPrev = prev; }

        if (value == mHead) { mHead = next; }
        if (value == mTail) { mTail = prev; }
        return value;
    }

    T *doRemove(T *value) {
        doDetach(value);
        value->mPrev = value->mNext = nullptr;
        return value;
    }

    T *doInsert(T *prev, T *value) {
        assert(value->mPrev == nullptr && value->mNext == nullptr);

        auto *next = prev ? prev->mNext : mHead;
        value->mPrev = prev;
        value->mNext = next;

        if (prev == nullptr) { mHead = value; } else { prev->mNext = value; }
        if (next == nullptr) { mTail = value; } else { next->mPrev = value; }
        return value;
    }

public:
    explicit LinkedList() = default;
    NO_COPY(LinkedList)

    T* removeFirst()         { return empty() ? nullptr : doRemove(mHead); }
    T* addFirst(T *value)    { return doInsert(nullptr, value); }
    T* addLast(T *value)     { return doInsert(mTail, value); }

    /** 从链表中移除节点，并清零节点自身的 mPrev/mNext。 */
    T* remove(T *value)      { return doRemove(value); }

    /**
     * 从链表中解除节点，但保留节点自身的 mPrev/mNext 不变。
     * 适用于节点移除后仍需沿链表方向传递事件的场景（如 ChannelPipeline）。
     */
    T* unlink(T *value)      { return doDetach(value); }

    /** 在 prev 之后插入 value；prev 为 nullptr 时插入到链表头部。 */
    T* insertAfter(T *prev, T *value) { return doInsert(prev, value); }

    bool contains(T *value) const {
        for (auto it = mHead; it; it = it->mNext) {
            if (it == value) return true;
        }
        return false;
    }

    [[nodiscard]] T*       first()       { return mHead; }
    [[nodiscard]] const T* first() const { return mHead; }
    [[nodiscard]] T*       last()        { return mTail; }
    [[nodiscard]] const T* last()  const { return mTail; }
    [[nodiscard]] bool     empty() const { return mHead == nullptr; }
};

} // namespace hysburg

#endif
