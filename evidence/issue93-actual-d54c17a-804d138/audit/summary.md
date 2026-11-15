# Independent audit summary

The independent audit concluded **PASS — bounded actual-run acceptance**. It found no acceptance failure in launch/process receipts, raw extraction/query/decode evidence, independent BQRS re-decodes, source-derived observation multiset, exact grant joins, and full report comparison. This is an operational bounded-run conclusion, not cryptographic attestation.

Verified outcomes: routing 1 input/1 plain with all other routing counts zero; successful extraction diagnostic 1, extraction errors 0; 21 source observations and declarations; 18 grant-represented methods; 38 selected grant IDs from a 110-row unique-ID catalog; source-only names `getInitList`, `getUSBDevices`, `setInitAction`; grant-only 0; `getMountPoints` retains four exact IDs. Three independent BQRS re-decodes exited zero and matched original decoded CSV bytes exactly.

Audit confirmed all 21 execution phase receipts zero, 29 approval references and 1,194 inventoried files matching, complete approved input pathset exact before/after, and original tracked consumer files unchanged. The independent source scan is pin-specific, not a general parser or a newly blinded review.

Producer identity: merged revision `d54c17a8cefc43ef9cde36d65558c986348aa7b2` was independently verified tree-equal (`b259eb7fb16cbfe6669a8e434d6493c90b393fdb`) to the exported producer PR-head, but execution used that tree-equal export, **not a checkout of the merge commit**. Consumer actually executed was `804d1386c54f4c273ca593e5dd2051636aa19245`; this evidence-only commit is later and was not executed.

Limitations: extractor binary was reused byte-pinned, not rebuilt, and no binary-to-source build attestation is supplied. This is not OS/runtime/crypto attestation and does not establish runtime registration, reachability, authorization, denial, ACL defect, or security. Source-only unmatched methods are not denials. Historical report reference fields remain unchanged and are not run pins.
