
#ifndef HYSBURG_BYTEBUF_HPP
#define HYSBURG_BYTEBUF_HPP

#include <cstring>
#include "Util.hpp"

namespace hysburg
{

class ByteBuf
{
public:
    struct Allocator {
        [[nodiscard]]
        uint8_t *alloc(size_t size) const noexcept {
            (void) this;
            return static_cast<uint8_t*>(::malloc(size));
        }

        [[nodiscard]]
        uint8_t *realloc(uint8_t *old, size_t size) const noexcept {
            (void) this;
            return static_cast<uint8_t*>(::realloc(old, size));
        }

        void free(uint8_t *ptr) const noexcept {
            (void) this;
            ::free(ptr);
        }
    };

private:
    uint8_t *mData = nullptr;
    size_t mCapacity = 0;
    size_t mReadIndex = 0;
    size_t mWriteIndex = 0;

    template<typename T>
    T readInteger() noexcept
    {
        if (sizeof(T) > readableBytes()) {
            return 0;
        }
        T value = *reinterpret_cast<T*>(mData + mReadIndex);
        mReadIndex += sizeof(T);
        return Numbers::reverseByte<T>(value);
    }

    void ensureWriteSpace(size_t len) noexcept
    {
        size_t targetWriteIndex = mWriteIndex + len;
        if (UNLIKELY(targetWriteIndex > mCapacity)) {
            // 要么扩容到 1.5 倍，要么扩容到所需大小
            size_t newCapacity = mCapacity + (mCapacity >> 1);
            newCapacity = std::max(newCapacity, targetWriteIndex);
            newCapacity = std::max(newCapacity, 256lu);
//            newCapacity = Numbers::align<16>(newCapacity);
            mData = Allocator().realloc(mData, newCapacity);
            mCapacity = newCapacity;
        }
    }

    template<typename T>
    void writeInteger(T value) noexcept
    {
        ensureWriteSpace(sizeof(T));
        *reinterpret_cast<T *>(mData + mWriteIndex) = Numbers::reverseByte<T>(value);
        mWriteIndex += sizeof(T);
    }

public:
    explicit ByteBuf() noexcept = default;

    explicit ByteBuf(size_t capacity) noexcept {
        mCapacity = capacity;
        mData = Allocator().alloc(capacity);
    }

    NO_COPY(ByteBuf);

    ~ByteBuf() noexcept { Allocator().free(mData); }

    uint8_t readByte() noexcept { return readInteger<int8_t>(); }
    uint16_t readShort() noexcept { return readInteger<int16_t>(); }
    uint32_t readInt() noexcept { return readInteger<int32_t>(); }
    uint64_t readLong() noexcept { return readInteger<int64_t>(); }

    size_t readBytes(void *out, size_t len) noexcept {
        auto consumed = std::min(len, readableBytes());
        memcpy(out, &mData[mReadIndex], consumed);
        mReadIndex += consumed;
        return consumed;
    }

    void writeByte(int8_t value) noexcept { writeInteger<int8_t>(value); }
    void writeShort(int16_t value) noexcept { writeInteger<int16_t>(value); }
    void writeInt(int32_t value) noexcept { writeInteger<int32_t>(value); }
    void writeLong(int64_t value) noexcept { writeInteger<int64_t>(value); }

    void writeBytes(const void *data, size_t len) noexcept {
        ensureWriteSpace(len);
        memcpy(&mData[mWriteIndex], data, len);
        mWriteIndex += len;
    }

    void writeBytes(const std::string_view &str) noexcept {
        writeBytes(str.data(), str.size());
    }


    void discardReadBytes() noexcept {
        memmove(mData, mData + mReadIndex, readableBytes());
        mWriteIndex -= mReadIndex;
        mReadIndex = 0;
    }

    void swap(ByteBuf &o) noexcept {
        std::swap(mData, o.mData);
        std::swap(mCapacity, o.mCapacity);
        std::swap(mReadIndex, o.mReadIndex);
        std::swap(mWriteIndex, o.mWriteIndex);
    }

    void cumulate(ByteBuf &o) noexcept {
        if (readableBytes() == 0) {
            swap(o);
        } else {
            writeBytes(o.readData(), o.readableBytes());
            o.readIndex(o.writeIndex());
        }
    }

    void release() noexcept {
        grab(nullptr, 0);
    }

    void *data() const noexcept { return mData; }
    size_t capacity() const noexcept { return mCapacity; }

    void *readData() const noexcept { return mData + mReadIndex; }
    void *writeData() const noexcept { return mData + mWriteIndex; }

    size_t readIndex() const noexcept { return mReadIndex; }
    size_t writeIndex() const noexcept { return mWriteIndex; }

    size_t readableBytes() const noexcept { return mWriteIndex - mReadIndex; }
    size_t writableBytes() const noexcept { return mCapacity - mWriteIndex; }

//    bool empty() const noexcept { return mSize == 0; }

    void grab(uint8_t *data, size_t capacity) noexcept {
        Allocator().free(mData);
        mData = data;
        mCapacity = capacity;
        mReadIndex = mWriteIndex = 0;
    }

    void readIndex(size_t index) noexcept { mReadIndex = index; }
    void writeIndex(size_t index) noexcept { mWriteIndex = index; }

    void clear() noexcept { mReadIndex = mWriteIndex = 0; }

    void offsetReader(ssize_t offset) noexcept { mReadIndex += offset; }
    void offsetWriter(ssize_t offset) noexcept { mWriteIndex += offset; }
};
}

#endif // HYSBURG_BYTEBUF_HPP
