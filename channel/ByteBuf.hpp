
#ifndef HYSBURG_BYTEBUF_HPP
#define HYSBURG_BYTEBUF_HPP

#include <cstring>
#include "Util.hpp"

namespace hysburg
{

class ByteBuf
{
    uint8_t *mData = nullptr;
    size_t mCapacity = 0;
    size_t mReadIndex = 0;
    size_t mWriteIndex = 0;

    template<typename T>
    T readInteger() noexcept
    {
        CHECK(sizeof(T) <= readableBytes(),
              "space access its capacity, %zu %zu",
              sizeof(T), readableBytes())

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
            mData = static_cast<uint8_t *>(realloc(mData, newCapacity));
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

    explicit ByteBuf(size_t capacity) noexcept:
            mData(static_cast<uint8_t *>(malloc(capacity))),
            mCapacity(capacity) {
    }

    explicit ByteBuf(std::unique_ptr<uint8_t> buf, size_t capacity) noexcept:
            mData(buf.release()), mCapacity(capacity) {
    }

    NO_COPY(ByteBuf);

    ~ByteBuf() noexcept { free(mData); }

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

    void transferFrom(ByteBuf &src) noexcept {
        if (readableBytes() == 0) {
            swap(src);
        } else {
            writeBytes(src.data() + src.readIndex(), src.readableBytes());
            src.clear();
        }
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

    uint8_t *data() const noexcept { return mData; }
    size_t capacity() const noexcept { return mCapacity; }

    uint8_t *readData() const noexcept { return mData + mReadIndex; }
    uint8_t *writeData() const noexcept { return mData + mWriteIndex; }

    size_t readIndex() const noexcept { return mReadIndex; }
    size_t writeIndex() const noexcept { return mWriteIndex; }

    size_t readableBytes() const noexcept { return mWriteIndex - mReadIndex; }

    size_t writableBytes() const noexcept { return mCapacity - mWriteIndex; }

//    bool empty() const noexcept { return mSize == 0; }

    void readIndex(size_t index) noexcept { mReadIndex = index; }
    void writeIndex(size_t index) noexcept { mWriteIndex = index; }

    void clear() noexcept { mReadIndex = mWriteIndex = 0; }
};
}

#endif // HYSBURG_BYTEBUF_HPP
