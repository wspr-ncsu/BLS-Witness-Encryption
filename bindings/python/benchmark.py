# flake8: noqa: E501
import time
import secrets

from blspy import (
    BasicSchemeMPL,
    G1Element,
    G2Element,
    PrivateKey,
)

from witencpy import (Scheme, CipherText, OTP)

cts = []
numIters = 1000
sk: PrivateKey = BasicSchemeMPL.key_gen(secrets.token_bytes(32))
pk: G1Element = sk.get_g1()
tag: bytes = secrets.token_bytes(32)
sig: G2Element = BasicSchemeMPL.sign(sk, tag)

def startStopwatch():
    return time.perf_counter()

def endStopwatch(test_name, start, numIters):
    end_time = time.perf_counter()
    duration = end_time - start
    print("\n%s\nTotal: %d runs in %0.1f ms\nAvg: %f"
        % (test_name, numIters, duration * 1000, duration * 1000 / numIters))

def check_correctness():
    msg = b"Hello World!"
    ct: CipherText = Scheme.encrypt(bytes(pk), tag, msg)
    dec: bytes = bytes(Scheme.decrypt(bytes(sig), ct))
    assert msg == dec

def bench_encryptions():
    start = startStopwatch()
    for i in range(numIters):
        msg = b"%d" % i
        ct = Scheme.encrypt(bytes(pk), tag, msg)
        cts.append(ct)
        
    endStopwatch("WitEnc::Encryption", start, numIters)
    
def bench_decryptions():
    start = startStopwatch()
    for ct in cts:
       Scheme.decrypt(bytes(sig), ct)
        
    endStopwatch("WitEnc::Decryption", start, numIters)

def bench_cts():
    bts = []
    impcts = []
    
    start = startStopwatch()
    for ct in cts:
       bts.append(bytes(ct))
    endStopwatch("Ciphertext::Serialize", start, numIters)
    
    start = startStopwatch()
    for bt in bts:
       ct = CipherText.from_bytes(bt)
       ct.validate()
       impcts.append(ct)
    endStopwatch("Ciphertext::Deserialize", start, numIters)
    
    for index, ct in enumerate(cts):
        assert ct == impcts[index]
        
def clear_cts():
    cts.clear()
    
def check_otp_correctness():
    msg = b"Hello World!"
    ct: bytes = bytes(OTP.encrypt(tag, msg))
    dec: bytes = bytes(OTP.decrypt(tag, ct))
    assert msg == dec
    
def bench_otp_encryptions():
    start = startStopwatch()
    
    for i in range(numIters):
        msg = b"%d" % i
        ct = bytes(OTP.encrypt(tag, msg)) # using tag as key
        cts.append(ct)
        
    endStopwatch("OTP::Encryption", start, numIters)
    
def bench_otp_decryptions():
    start = startStopwatch()
    for ct in cts:
       OTP.decrypt(tag, ct)
        
    endStopwatch("OTP::Decryption", start, numIters)

if __name__ == "__main__":
    check_correctness()
    bench_encryptions()
    bench_decryptions()
    bench_cts()

    clear_cts()

    check_otp_correctness()
    bench_otp_encryptions()
    bench_otp_decryptions()