# Challenge

>Your friend, in last year at university, is super excited because he just learned about MapReduce and parallel computing. However, he kept his cluster exposed to the internet, saying it should be fine because he enabled authentication. Decided to give him a lesson, you start your favorite sniffing tool...
>
The flag is the password used for authentication between the master and the worker, surrounded by the flag format RM{}.
>
Author: [Elf](https://cypelf.fr/)
>
Hint: Feel free to dig into the source code of spark to find out what specific encoding may be applied to both the username and the password

# Writeup

## SASL Auth
After opening the pcap file with Wireshark we can see the following TCP stream :
![Pasted image 20250512222917](https://github.com/user-attachments/assets/a4e48eb8-f499-491e-88a1-f2912366b9c8)

We can see the username "sparkSaslUser" meaning that we're dealing with SASL (Simple Authentication and Security Layer) auth in Spark application. The algorithm being "md5-sess" suggests that this is SASL DIGEST-MD5.

Searching for SASL MD5 RFC leads us to [RFC2831](https://datatracker.ietf.org/doc/html/rfc2831) which is about "Using Digest Authentication as a SASL Mechanism". 
Basically, this authentication method relies on both client and server calculating a response value from certain parameters exchanged and the password. The client then sends this response value and if it matches the one expected by the server, the client is authenticated.

According to the documentation, the response value depends on:

- Nonce (HSWNY+2ywnImSkjHQBsAy8eBUfZW7FH18LggOtuH)
- Cnonce (mzel+1YigqLpb16JXiAf2zLlfh2dDNaApPBny7PH)
- Nonce-count (00000001)
- Realm (default)
- Username (sparkSaslUser)
- Password
- Digest-uri (null/default)
- Method (AUTHENTICATE)

and equals to :

HEX( KD ( HEX(H(A1)),
                 { nonce-value, ":" nc-value, ":",
                   cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))

with A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
           ":", nonce-value, ":", cnonce-value, ":", authzid-value }

and A2 = { "AUTHENTICATE:", digest-uri-value }

H being the 16 octet MD5 hash [RFC 1321] of the octet string s.
KD(k, s) being H({k, ":", s}), i.e., the 16 octet hash of the string k, a colon and the string s.
HEX being the representation of the 16 octet MD5 hash n as a string of 32 hex digits.

In this PCAP, we have response = f8ebc5dbbd088e71874a2213a3590e6c. 
Having all parameters but the password, we can try to brute force it by computing response values for each password of a wordlist and comparing to the response value. 

Here is my python implementation :

```python
import base64
import hashlib
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import base64

# PCAP parameters
user = "sparkSaslUser"
realm = "default"
nonce = "HSWNY+2ywnImSkjHQBsAy8eBUfZW7FH18LggOtuH"
cnonce = "mzel+1YigqLpb16JXiAf2zLlfh2dDNaApPBny7PH"
nc = "00000001"
qop = "auth"
digest_uri = "null/default"
expected_response = "f8ebc5dbbd088e71874a2213a3590e6c"

def compute_response(username, password, realm, nonce, method, digest_uri, cnonce, nc, qop):
    charset = 'utf-8'

    # A1 = MD5(username:realm:password) + ":" + nonce + ":" + cnonce (as bytes)
    a1_str = f"{username}:{realm}:{password}"
    ha1 = hashlib.md5(a1_str.encode(charset)).digest()  # NOTE: keep as bytes
    a1_final = ha1 + b':' + nonce.encode(charset) + b':' + cnonce.encode(charset)
    ha1_final = hashlib.md5(a1_final).hexdigest()

    # A2
    a2 = f"{method}:{digest_uri}"
    ha2 = hashlib.md5(a2.encode(charset)).hexdigest()

    response_str = f"{ha1_final}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"
    response = hashlib.md5(response_str.encode(charset)).hexdigest()

    return {
        'username': username,
        'realm': realm,
        'nonce': nonce,
        'cnonce': cnonce,
        'nc': nc,
        'qop': qop,
        'digest-uri': digest_uri,
        'response': response,
        'charset': charset
    }

def compute_digest(password):
    response_dict = compute_response(
        username=user,
        password=password,
        realm=realm,
        nonce=nonce,
        method="AUTHENTICATE",
        digest_uri=digest_uri,
        cnonce=cnonce,
        nc="00000001",
        qop="auth"
    )

    return response_dict["response"]

def check_password(pwd):
    response = compute_digest(pwd)
    if response == expected_response:
        return pwd
    return None

def main():
    from itertools import islice
    wordlist_path = "/usr/share/wordlists/rockyou.txt"

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = f.read().splitlines()

    total = len(passwords)
    print(f"[i] Testing {total} passwords using {cpu_count()} cores...")

    found = None
    with Pool(cpu_count()) as pool:
        for result in tqdm(pool.imap_unordered(check_password, passwords, chunksize=1000), total=total):
            if result:
                found = result
                pool.terminate()
                break

    if found:
        print(f"\n[+] Found password: {found}")
        print(f"Flag: RM{{{found}}}")
    else:
        print("\n[-] Password not found in the provided wordlist.")

if __name__ == "__main__":
    main()
```

It's important to note the difference between .digest() and .hexdigest(), with the first corresponding to RFC H() function and the latter corresponding to RFC HEX(H()) function.

Unfortunately, no password matched, even with different wordlists : rockyou, richelieu, custom, etc.
First I checked my implementation against the example provided at the end of the RFC :
![Pasted image 20250512234845](https://github.com/user-attachments/assets/2572da0b-5fe2-4980-8ceb-129825a73f5b)
I added this python function to test it :
```python
def test_rfc_example():
    # Inputs from RFC 2831 Appendix A
    expected_response = "d388dad90d4bbd760a152321f2143af7"

    response_dict = compute_response(
        username="chris",
        password="secret",
        realm="elwood.innosoft.com",
        nonce="OA6MG9tEQGm2hh",
        method="AUTHENTICATE",
        digest_uri="imap/elwood.innosoft.com",
        cnonce="OA6MHXh6VqTrRk",
        nc="00000001",
        qop="auth"
    )

    actual_response = response_dict["response"]
    print("RFC Expected Response:", expected_response)
    print("Computed Response     :", actual_response)
    assert actual_response == expected_response, "Test failed!"
    print("✅ Test passed.")
```
And it passed. 

## Spark implementation

If our python implementation is correct, then maybe Spark implementation of SASL DIGEST-MD5 auth differs from the RFC. This is what suggets the hint provided during the CTF : 
> Feel free to dig into the source code of spark to find out what specific encoding may be applied to both the username and the password

Searching "sasl" in [Spark Github](https://github.com/apache/spark) leads us to this code :
![Pasted image 20250512235703](https://github.com/user-attachments/assets/9d5f1afb-2672-4d41-8d14-2a022cced30d)
in this file : https://github.com/apache/spark/blob/37028fafc4f9fc873195a88f0840ab69edcf9d2b/common/network-common/src/main/java/org/apache/spark/network/sasl/SparkSaslClient.java

We find this interesting function handling the secrets :
```
private class ClientCallbackHandler implements CallbackHandler {
    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {

      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback nc) {
          logger.trace("SASL client callback: setting username");
          nc.setName(encodeIdentifier(secretKeyHolder.getSaslUser(secretKeyId)));
        } else if (callback instanceof PasswordCallback pc) {
          logger.trace("SASL client callback: setting password");
          pc.setPassword(encodePassword(secretKeyHolder.getSecretKey(secretKeyId)));
        } else if (callback instanceof RealmCallback rc) {
          logger.trace("SASL client callback: setting realm");
          rc.setText(rc.getDefaultText());
        } else if (callback instanceof RealmChoiceCallback) {
          // ignore (?)
        } else {
          throw new UnsupportedCallbackException(callback, "Unrecognized SASL DIGEST-MD5 Callback");
        }
      }
    }
  }
```
The username is first encoded through the `encodeIdentifier` function, and the password through the `encodePassword` one.
Upon inspection, these two functions simply Base64-encode the secrets if they are not null.

So, we need to adapt the python script with :
```python
user = "c3BhcmtTYXNsVXNlcg=="

def main():
...
passwords = [base64.b64encode(pwd.encode()).decode() for pwd in passwords]
...
```

Running it against the rockyou wordlist yields a result : 
![Pasted image 20250513000549](https://github.com/user-attachments/assets/c5c2dbfa-7acd-465b-87b1-c72ca282a55f)
X19IYUNrRXJfXw== base64 decoded is \_\_HaCkEr\_\_, the flag is then RM{\_\_HaCkEr\_\_}.

# Acknowledgments

Thanks to [Elf](https://cypelf.fr/) for this great CTF, which was an opportunity to learn about SASL auth. Implementing the RFC in python was a bit challenging, but mostly required focus and time.
