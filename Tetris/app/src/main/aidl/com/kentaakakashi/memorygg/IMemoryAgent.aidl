package com.kentaakakashi.memorygg;
interface IMemoryAgent {
    String getInfo();
    String authorize(String token);
    String selfTest();
    String scanFirst(String value, int type);
    String scanNext(String value, int type, int condition);
    String writeValue(long address, String value, int type);
    String clearScan();
    int getProbeValue();
    int setProbeValue(int value);
}
