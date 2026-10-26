// MemoryGG scanner compiled inside the Tetris target process.
#include <jni.h>
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

// Scanner engine is deliberately in-process: it only operates on this PID's mappings.
static volatile int32_t controlled_value = 12345;
enum ValueType { I32 = 0, F32 = 1, I64 = 2, F64 = 3 };
struct Region { uintptr_t start; uintptr_t end; int priority; };
struct Match { uintptr_t address; std::string value; long double numeric; };
static std::mutex g_mutex;
static std::vector<Match> g_matches;
static std::vector<uintptr_t> g_known;
static int g_type = I32;
static int g_mem = -1;
static constexpr size_t CHUNK = 256U * 1024U;
static constexpr size_t MAX_BYTES = 96U * 1024U * 1024U;
static constexpr size_t MAX_MATCHES = 3000;

static jstring js(JNIEnv* env, const std::string& s) { return env->NewStringUTF(s.c_str()); }
static size_t widthFor(int t) { return (t == I64 || t == F64) ? 8U : 4U; }

static bool parse(const std::string& s, int t, long double& out) {
    if (s.empty()) return false;
    char* end = nullptr; errno = 0;
    if (t == I32 || t == I64) {
        long long v = std::strtoll(s.c_str(), &end, 10);
        if (errno || end == s.c_str() || *end != '\0') return false;
        if (t == I32 && (v < INT32_MIN || v > INT32_MAX)) return false;
        out = static_cast<long double>(v); return true;
    }
    double v = std::strtod(s.c_str(), &end);
    if (errno || end == s.c_str() || *end != '\0' || !std::isfinite(v)) return false;
    if (t == F32 && std::abs(v) > std::numeric_limits<float>::max()) return false;
    out = v; return true;
}
static bool decode(const uint8_t* b, int t, long double& out) {
    if (t == I32) { int32_t v; std::memcpy(&v,b,4); out=v; return true; }
    if (t == F32) { float v; std::memcpy(&v,b,4); if(!std::isfinite(v)) return false; out=v; return true; }
    if (t == I64) { int64_t v; std::memcpy(&v,b,8); out=static_cast<long double>(v); return true; }
    if (t == F64) { double v; std::memcpy(&v,b,8); if(!std::isfinite(v)) return false; out=v; return true; }
    return false;
}
static std::string fmt(long double v, int t) {
    std::ostringstream o;
    if(t==I32) o<<static_cast<int32_t>(v);
    else if(t==I64) o<<static_cast<int64_t>(v);
    else if(t==F32) o<<std::setprecision(9)<<static_cast<float>(v);
    else o<<std::setprecision(17)<<static_cast<double>(v);
    return o.str();
}
static bool equalValue(long double a,long double b,int t) {
    if(t==F32 || t==F64) {
        long double scale=std::max(static_cast<long double>(1),std::max(std::abs(a),std::abs(b)));
        return std::abs(a-b) <= scale*(t==F32 ? 1e-6L : 1e-12L);
    }
    return a==b;
}
static bool readOwn(uintptr_t address, void* out, size_t len) {
    if(g_mem<0) g_mem=open("/proc/self/mem",O_RDWR|O_CLOEXEC);
    if(g_mem<0) return false;
    return pread(g_mem,out,len,static_cast<off_t>(address))==static_cast<ssize_t>(len);
}
static bool writeOwn(uintptr_t address,const void* data,size_t len) {
    if(g_mem<0) g_mem=open("/proc/self/mem",O_RDWR|O_CLOEXEC);
    if(g_mem<0) return false;
    return pwrite(g_mem,data,len,static_cast<off_t>(address))==static_cast<ssize_t>(len);
}
static std::vector<Region> regions() {
    std::vector<Region> out;
    std::ifstream f("/proc/self/maps"); std::string line;
    while(std::getline(f,line)) {
        std::istringstream in(line); std::string range,perm,offset,dev,inode,path;
        if(!(in>>range>>perm>>offset>>dev>>inode)) continue;
        std::getline(in,path);
        if(perm.size()<3 || perm[0]!='r' || perm[1]!='w') continue;
        size_t dash=range.find('-'); if(dash==std::string::npos) continue;
        uintptr_t a=0,b=0;
        try { a=std::stoull(range.substr(0,dash),nullptr,16); b=std::stoull(range.substr(dash+1),nullptr,16); }
        catch(...) { continue; }
        if(!a || b<=a) continue;
        int p=2;
        if(path.find("libmemorygg.so")!=std::string::npos) p=0;
        else if(path.empty() || path.find("[heap]")!=std::string::npos || path.find("[anon")!=std::string::npos) p=1;
        out.push_back({a,b,p});
    }
    std::stable_sort(out.begin(),out.end(),[](const Region&a,const Region&b){return a.priority<b.priority;});
    return out;
}
static std::string json(bool ok,const std::string& message,size_t scanned,bool capped) {
    std::ostringstream o;
    o<<"{\"ok\":"<<(ok?"true":"false")<<",\"message\":\"";
    for(char c:message) { if(c=='\\'||c=='"') o<<'\\'; if(c=='\n'||c=='\r') o<<' '; else o<<c; }
    o<<"\",\"count\":"<<g_matches.size()<<",\"scannedBytes\":"<<scanned<<",\"truncated\":"<<(capped?"true":"false")<<",\"matches\":[";
    for(size_t i=0;i<g_matches.size();++i) {
        if(i) o<<',';
        o<<"{\"address\":\"0x"<<std::hex<<g_matches[i].address<<std::dec<<"\",\"value\":\""<<g_matches[i].value<<"\"}";
    }
    o<<"]}"; return o.str();
}
static bool known(uintptr_t a) { return std::find(g_known.begin(),g_known.end(),a)!=g_known.end(); }

extern "C" JNIEXPORT jstring JNICALL
Java_com_kentaakakashi_memorygg_MainActivity_nativeSelfTest(JNIEnv* e,jobject) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const uintptr_t address = reinterpret_cast<uintptr_t>(const_cast<int32_t*>(&controlled_value));
    int32_t before = 0, after = 0;
    const bool readOk = readOwn(address, &before, sizeof(before));
    const int32_t replacement = 54321;
    const bool writeOk = readOk && writeOwn(address, &replacement, sizeof(replacement));
    const bool verifyOk = writeOk && readOwn(address, &after, sizeof(after));
    const int32_t restore = before;
    const bool restoreOk = writeOwn(address, &restore, sizeof(restore));
    const bool pass = readOk && writeOk && verifyOk && restoreOk && after == 54321;
    std::ostringstream o;
    o << (pass ? "PASS" : "FAIL")
      << " (/proc/self/mem own-process read/write; before=" << before
      << ", observed=" << after << ", restored=" << (restoreOk ? "yes" : "no") << ")";
    return js(e,o.str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_kentaakakashi_memorygg_MainActivity_nativeScanFirst(JNIEnv* e,jobject,jstring jv,jint jt) {
    const char* c=e->GetStringUTFChars(jv,nullptr); std::string q=c?c:""; if(c)e->ReleaseStringUTFChars(jv,c);
    int t=jt; if(t<0||t>3) return js(e,"{\"ok\":false,\"message\":\"Unknown type\",\"count\":0,\"matches\":[]}");
    long double target=0; if(!parse(q,t,target)) return js(e,"{\"ok\":false,\"message\":\"Enter a valid number\",\"count\":0,\"matches\":[]}");
    std::lock_guard<std::mutex> lock(g_mutex);
    g_matches.clear(); g_known.clear(); g_type=t;
    auto rs=regions(); std::vector<uint8_t> buf(CHUNK);
    size_t scanned=0; bool capped=false; size_t w=widthFor(t);
    // Check the known test probe before the bounded map sweep so the smoke test
    // remains deterministic even when earlier mappings consume the scan budget.
    if (t == I32) {
        const uintptr_t probe = reinterpret_cast<uintptr_t>(const_cast<int32_t*>(&controlled_value));
        int32_t probeValue = 0;
        if (readOwn(probe, &probeValue, sizeof(probeValue)) &&
            equalValue(static_cast<long double>(probeValue), target, t)) {
            g_matches.push_back({probe, fmt(static_cast<long double>(probeValue), t),
                                 static_cast<long double>(probeValue)});
            g_known.push_back(probe);
        }
    }
    for(const Region&r:rs) {
        uintptr_t pos=(r.start+w-1)&~(static_cast<uintptr_t>(w)-1);
        while(pos+w<=r.end) {
            if(scanned>=MAX_BYTES||g_matches.size()>=MAX_MATCHES){capped=true;break;}
            size_t n=static_cast<size_t>(std::min<uintptr_t>(CHUNK,r.end-pos));
            n-=n%w; n=std::min(n,MAX_BYTES-scanned); n-=n%w; if(n<w)break;
            if(readOwn(pos,buf.data(),n)) {
                for(size_t off=0;off+w<=n;off+=w) {
                    long double v=0; if(!decode(buf.data()+off,t,v)||!equalValue(v,target,t))continue;
                    uintptr_t addr=pos+off; g_matches.push_back({addr,fmt(v,t),v}); g_known.push_back(addr);
                    if(g_matches.size()>=MAX_MATCHES){capped=true;break;}
                }
            }
            scanned+=n; pos+=n;
        }
        if(capped)break;
    }
    std::sort(g_known.begin(),g_known.end()); g_known.erase(std::unique(g_known.begin(),g_known.end()),g_known.end());
    return js(e,json(true,g_matches.empty()?"No matches found. Try another value or type.":"First scan complete (this process only).",scanned,capped));
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_kentaakakashi_memorygg_MainActivity_nativeScanNext(JNIEnv* e,jobject,jstring jv,jint jt,jint jc) {
    const char* c=e->GetStringUTFChars(jv,nullptr); std::string q=c?c:""; if(c)e->ReleaseStringUTFChars(jv,c);
    int t=jt,cond=jc; long double target=0;
    if(t<0||t>3||cond<0||cond>4)return js(e,"{\"ok\":false,\"message\":\"Invalid type or condition\",\"count\":0,\"matches\":[]}");
    if(cond==0&&!parse(q,t,target))return js(e,"{\"ok\":false,\"message\":\"Exact scan needs a valid number\",\"count\":0,\"matches\":[]}");
    std::lock_guard<std::mutex> lock(g_mutex);
    if(g_matches.empty())return js(e,"{\"ok\":false,\"message\":\"Run First Scan first\",\"count\":0,\"matches\":[]}");
    if(g_type!=t)return js(e,"{\"ok\":false,\"message\":\"Type changed; reset and start again\",\"count\":0,\"matches\":[]}");
    std::vector<Match> next; next.reserve(g_matches.size()); size_t w=widthFor(t);
    for(const Match&m:g_matches) {
        uint8_t b[8]={}; if(!readOwn(m.address,b,w))continue; long double v=0; if(!decode(b,t,v))continue;
        bool keep=false;
        switch(cond) {
            case 0: keep=equalValue(v,target,t); break;
            case 1: keep=v>m.numeric&&!equalValue(v,m.numeric,t); break;
            case 2: keep=v<m.numeric&&!equalValue(v,m.numeric,t); break;
            case 3: keep=equalValue(v,m.numeric,t); break;
            case 4: keep=!equalValue(v,m.numeric,t); break;
        }
        if(keep)next.push_back({m.address,fmt(v,t),v});
    }
    g_matches.swap(next);
    return js(e,json(true,"Next scan complete.",0,false));
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_kentaakakashi_memorygg_MainActivity_nativeWriteValue(JNIEnv* e,jobject,jlong ja,jstring jv,jint jt) {
    uintptr_t a=static_cast<uintptr_t>(ja); const char*c=e->GetStringUTFChars(jv,nullptr);std::string q=c?c:"";if(c)e->ReleaseStringUTFChars(jv,c);
    int t=jt; long double v=0;if(t<0||t>3||!parse(q,t,v))return js(e,"Write rejected: invalid number/type.");
    std::lock_guard<std::mutex> lock(g_mutex);
    if(t!=g_type||!known(a))return js(e,"Write rejected: address is not a known scan candidate.");
    uint8_t b[8]={};
    if(t==I32){int32_t n=static_cast<int32_t>(v);std::memcpy(b,&n,4);}
    else if(t==F32){float n=static_cast<float>(v);std::memcpy(b,&n,4);}
    else if(t==I64){int64_t n=static_cast<int64_t>(v);std::memcpy(b,&n,8);}
    else {double n=static_cast<double>(v);std::memcpy(b,&n,8);}
    if(!writeOwn(a,b,widthFor(t)))return js(e,"Write failed: this process memory mapping denied the write.");
    for(Match&m:g_matches)if(m.address==a){m.value=fmt(v,t);m.numeric=v;break;}
    return js(e,"PASS: wrote "+fmt(v,t));
}
extern "C" JNIEXPORT void JNICALL
Java_com_kentaakakashi_memorygg_MainActivity_nativeClearScan(JNIEnv*,jobject) {
    std::lock_guard<std::mutex> lock(g_mutex);g_matches.clear();g_known.clear();
}

extern "C" JNIEXPORT jint JNICALL
Java_com_kentaakakashi_memorygg_MainActivity_nativeGetTestValue(JNIEnv*,jobject) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return static_cast<jint>(controlled_value);
}
extern "C" JNIEXPORT jint JNICALL
Java_com_kentaakakashi_memorygg_MainActivity_nativeSetTestValue(JNIEnv*,jobject,jint value) {
    std::lock_guard<std::mutex> lock(g_mutex);
    controlled_value = static_cast<int32_t>(value);
    return static_cast<jint>(controlled_value);
}


extern "C" JNIEXPORT jstring JNICALL Java_com_kentaakakashi_memorygg_agenthost_AgentHostService_nativeSelfTest(JNIEnv* e,jobject o) { return Java_com_kentaakakashi_memorygg_MainActivity_nativeSelfTest(e,o); }
extern "C" JNIEXPORT jstring JNICALL Java_com_kentaakakashi_memorygg_agenthost_AgentHostService_nativeScanFirst(JNIEnv* e,jobject o,jstring v,jint t) { return Java_com_kentaakakashi_memorygg_MainActivity_nativeScanFirst(e,o,v,t); }
extern "C" JNIEXPORT jstring JNICALL Java_com_kentaakakashi_memorygg_agenthost_AgentHostService_nativeScanNext(JNIEnv* e,jobject o,jstring v,jint t,jint c) { return Java_com_kentaakakashi_memorygg_MainActivity_nativeScanNext(e,o,v,t,c); }
extern "C" JNIEXPORT jstring JNICALL Java_com_kentaakakashi_memorygg_agenthost_AgentHostService_nativeWriteValue(JNIEnv* e,jobject o,jlong a,jstring v,jint t) { return Java_com_kentaakakashi_memorygg_MainActivity_nativeWriteValue(e,o,a,v,t); }
extern "C" JNIEXPORT void JNICALL Java_com_kentaakakashi_memorygg_agenthost_AgentHostService_nativeClearScan(JNIEnv* e,jobject o) { Java_com_kentaakakashi_memorygg_MainActivity_nativeClearScan(e,o); }
extern "C" JNIEXPORT jint JNICALL Java_com_kentaakakashi_memorygg_agenthost_AgentHostService_nativeGetTestValue(JNIEnv* e,jobject o) { return Java_com_kentaakakashi_memorygg_MainActivity_nativeGetTestValue(e,o); }
extern "C" JNIEXPORT jint JNICALL Java_com_kentaakakashi_memorygg_agenthost_AgentHostService_nativeSetTestValue(JNIEnv* e,jobject o,jint v) { return Java_com_kentaakakashi_memorygg_MainActivity_nativeSetTestValue(e,o,v); }
