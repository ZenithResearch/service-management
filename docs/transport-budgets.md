# Service native transport budgets

This source slice preserves the 65,536-byte public command/query reader and the
existing field shapes. It supports the current compact canonical Python producer
and compact `ensure_ascii=True` outer wrappers with bounded native Packet proof
and signed-context bytes. It does not provision identities, issue or sign
authority, qualify an installed target, or change readiness/default denial.

| Boundary | Bytes |
| --- | ---: |
| Public command/query | 65,536 |
| Packet proof | 16,384 |
| Fixed-integer bincode Packet v0 overhead | 69 |
| Complete Service Packet | 81,989 |
| Signed context | 65,536 |
| Compact `service.secs-envelope.v1` fixed JSON overhead | 77 |
| Native authority JSON | 295,127 |
| Canonical authority base64 | 393,504 characters |
| Compact `service.transport.v1` fixed JSON overhead | 66 |
| Canonical literal-Unicode HTTP wrapper maximum | 459,106 |
| Compact ASCII-escaped HTTP wrapper ceiling | 786,786 |
| Service helper typed metadata, including JSON framing | 65,536 |
| Service helper stdin ceiling | 491,658 |
| Service stdout decoder (unchanged) | 131,072 |

For `R=65,536`, `P=R+16,384+69=81,989`, `C=65,536`, authority is
`A=2P+2C+77=295,127`. Its canonical base64 length is `4*ceil(A/3)=393,504`.
The existing compact wrapper costs 66 fixed bytes and repeats the request. The
literal producer needs `R+B(A)+66=459,106` bytes. Allowed DEL expands from one
literal UTF-8 byte to six ASCII escape bytes under `ensure_ascii=True`, so the
conservative ceiling is `6R+B(A)+66=786,786`. Other whitespace or generic JSON
escaping remains subject to this same explicit outer admission ceiling; it is
not a promise to accept arbitrarily padded equivalents. Missing or malformed
authority is still denied by the receiver.

Before helper launch, Service checks its own request, Packet, context, metadata
and total stdin ceilings. It reads only the fixed Packet v0 length fields needed
to enforce proof/payload bounds and exact frame length. Native code still owns
cryptographic verification and Packet/request/context binding. This does not
assign authentication semantics to the reserved MAC or implement holder proof.
`2P+2R+2C+65,536=491,658` is below the shared helper's historical 9-MiB stdin cap.
The receiver policy file retains its separate historical 262,144-byte ceiling;
the legacy `X-Service-Authority` header retains 16,384 characters. The configured
native executable pin and its verification protocol remain operator-selected.

Each server admits at most two body allocations through request handling, with
nonblocking saturation using the existing `storage_unavailable` 503 envelope.
Each admitted body has an absolute five-second read deadline, checked between
at-most-64-KiB `read1` chunks, including a final deadline check. `read1` prevents a
buffered read from extending the deadline through repeated tiny socket reads.
The ordinary five-second socket timeout resumes for later handling/response.
Admission releases after success, parse rejection, EOF, timeout and handler
failure. Independent embedded servers have independent gates; deployment must
account for their aggregate resource use.

Service canonicalizes a parsed command/query before the native helper receives
`request_hex`. The reader may accept alternate number spellings, key order and
whitespace, but those raw bytes are not necessarily the native-bound bytes.
Opaque planning inputs support finite numbers and non-NUL controls/Unicode;
Python may round a decimal or change its spelling. The issuer profile must use
the actual reviewed Python canonical producer bytes and preserve them through
native code. Queries expose no opaque Unicode/control field. Their integer
tokens, field shapes and public size boundary are unchanged.

A 65,536-byte signed bincode context does not alone prove its JSON projection
fits 131,072 output bytes: control-bearing summary strings can expand. The Service
stdout decoder retains its unchanged 131,072-byte bound. The historical b044
helper has no independent stdout byte guard; the separately amended Runtime
helper source adds one. Compatibility with b044 is measured using its actual
returned output, without changing that artifact or treating it as the new helper.
Installed issuer qualification must satisfy the admitted helper/decoder output
bounds as well as the signed-context bound.

The dedicated tests distinguish inert size/framing buffers and in-memory HTTP
handler captures from cryptographic checks. Test-only synthetic native fixtures,
when enabled through the historical pinned helper, provide separate native
verification evidence. Neither kind of test admits production authority.
