package org.example;

public class Record {
    byte[] messages;
    byte mContentType;
    byte[] mVersion = new byte[2];
    int mLength;
    boolean end;
    public Record() {
        end = false;
    }

    public void addMessage(byte[] inBytes) {
        if (messages == null) {
            int length = inBytes.length;
            messages = new byte[length];
            System.arraycopy(inBytes, 0, messages, 0, length);
        } else {
            messages = Utils.concat(messages, inBytes);
        }
    }

    public RecordMsg getMessage() {
        byte[] payload = new byte[mLength];
        System.arraycopy(messages, RecordMsg.HEAD_SIZE, payload, 0, mLength);
        int length = messages.length - RecordMsg.HEAD_SIZE - mLength;
        if (length == 0) {
            end = true;
        } else {
            byte[] tmp = new byte[length];
            System.arraycopy(messages, RecordMsg.HEAD_SIZE + mLength, tmp, 0, length);
            messages = new byte[length];
            System.arraycopy(tmp, 0, messages, 0, length);
        }
        return new RecordMsg(mContentType, mVersion, payload);
    }

    public void initMessage() {
        mContentType = messages[0];
        System.arraycopy(messages, 1, mVersion, 0, 2);
        byte[] length = new byte[2];
        System.arraycopy(messages, 3, length, 0, 2);
        mLength = Utils.getLength(length, 2);
    }

    public boolean isEnd() {
        return end;
    }

    public boolean isEnough(int remainingLength) {
        initMessage();
        return remainingLength >= mLength;
    }
}
