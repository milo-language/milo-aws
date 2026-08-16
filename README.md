# aws

This is a package for the [Milo language](https://milo-language.github.io/milo/).

## Overview

Sign AWS requests, and talk to S3.

```milo
let signed = sign(req, creds, "us-east-1", "dynamodb", amzNow())
```

No SDK and no C dependency: SigV4 is HMAC-SHA256 over a canonical string, and
`std` already has the primitives. The signing is identical for every AWS
service, so `sign` works against DynamoDB, SQS or Lambda even though S3 is the
only client here.

One decision the library will not make for you. **S3 encodes the request path
once; every other AWS service encodes it twice**, so you pick `Request.forS3` or
`Request.new`. Nothing infers it from the service name you pass to `sign`,
because a wrong answer should look like a choice rather than an accident. That
mismatch is the most common cause of `SignatureDoesNotMatch`, and the error
tells you nothing about which end is wrong.

Absent rather than stubbed in v0.1: IMDSv2 and instance roles, AssumeRole/STS,
multipart and streaming uploads, retries, and virtual-hosted addressing.

Full API, the canonicalisation rules, the credential chain and error kinds:
[docs/api.md](docs/api.md).

## Installation

```bash
milo add github.com/milo-language/milo-aws
```

```milo
from "aws" import { Credentials, S3, Request, sign, presign, amzNow }
```

## Examples

### S3

```milo
from "aws" import { Credentials, S3 }

fn main(): i32 {
    let creds = Credentials.resolve()!          // env, then ~/.aws/credentials
    let s3 = S3.new("https://s3.us-east-1.amazonaws.com", "us-east-1", creds)

    s3.putObject("notes", "hello.txt", "hello from milo\n", "text/plain")!
    print(s3.getObject("notes", "hello.txt")!)

    for m in s3.listObjectsV2("notes", "")! {
        print($"{m.key} {m.size} bytes")
    }

    match s3.getObject("notes", "gone.txt") {
        Result.Ok(body) => {
            print(body)
        }
        Result.Err(e) => {
            print($"{e.code} {e.status} notFound={e.isNotFound()}")
        }
    }
    return 0
}
```

```
hello from milo

hello.txt 16 bytes
NoSuchKey 404 notFound=true
```

`listObjectsV2` follows continuation tokens to the end, so it returns everything
under the prefix rather than S3's first 1000 keys. Branch on `e.code`, which is
stable across regions and releases; `e.message` is prose and gets reworded.

### Signing a request for any service

```milo
from "aws" import { Credentials, Request, sign }

fn main(): i32 {
    let creds = Credentials.resolve()!

    var req = Request.new("POST", "https://dynamodb.us-east-1.amazonaws.com/")
    req.setHeader("content-type", "application/x-amz-json-1.0")
    req.setHeader("x-amz-target", "DynamoDB_20120810.ListTables")
    req.setBody("{}")

    // The timestamp is a parameter, not a clock read, so this is reproducible.
    let signed = sign(req, creds, "us-east-1", "dynamodb", "20150830T123600Z")

    print(signed.method + " " + signed.url)
    for h in signed.headers {
        print($"{h.name}: {h.value}")
    }
    return 0
}
```

```
POST https://dynamodb.us-east-1.amazonaws.com/
content-type: application/x-amz-json-1.0
host: dynamodb.us-east-1.amazonaws.com
x-amz-date: 20150830T123600Z
x-amz-target: DynamoDB_20120810.ListTables
authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/dynamodb/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=75214f17608dbd636679e18f6f89744844ae96fcd228b8147167152488d817de
```

`sign` and `presign` take the timestamp as a parameter because a signature is a
pure function of its inputs, and that is the only thing that makes it testable
against AWS's published vectors. A signer that reads the clock internally can
never reproduce a fixed one. `amzNow()` is the live answer when you want it.

`SignedRequest` carries everything that must go on the wire, `Host` included.
`sendSigned(signed)` will send it, or hand the parts to any client that
reproduces the `Host` header verbatim and does not follow redirects.

### A presigned URL

```milo
from "aws" import { Credentials, S3 }

fn main(): i32 {
    let creds = Credentials.resolve()!
    let s3 = S3.new("https://s3.us-east-1.amazonaws.com", "us-east-1", creds)

    // Good for five minutes, and carries no credentials a client must hold.
    print(s3.presignGet("my-bucket", "notes/hello.txt", 300, "20150830T123600Z"))
    return 0
}
```

```
https://s3.us-east-1.amazonaws.com/my-bucket/notes/hello.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=7fc0aa6beb8055f0a179921be2f114cde5ddd7ec55926762a5f17e368ba70a65
```

The credential, the timestamp and `X-Amz-Expires` move into the query string,
the payload becomes `UNSIGNED-PAYLOAD`, and the signature covers the query
rather than an `Authorization` header. Only `host` is signed unless you add
headers yourself: anything signed has to be *sent* by whoever fetches the URL,
and a browser will not send an `x-amz-*` header for you.
