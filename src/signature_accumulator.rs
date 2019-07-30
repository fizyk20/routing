// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    messages::RoutingMessage,
    sha3::Digest256,
    time::{Duration, Instant},
    BlsPublicKeySet, BlsPublicKeyShare, BlsSignature, BlsSignatureShare,
};
use itertools::Itertools;
use maidsafe_utilities::serialisation::serialise;
use std::collections::HashMap;

/// Time (in seconds) within which a message and a quorum of signatures need to arrive to
/// accumulate.
pub const ACCUMULATION_TIMEOUT: Duration = Duration::from_secs(30);

struct AccumulatorEntry {
    shares: HashMap<BlsPublicKeyShare, BlsSignatureShare>,
    timestamp: Instant,
}

#[derive(Default)]
pub struct SignatureAccumulator {
    msgs: HashMap<Digest256, AccumulatorEntry>,
}

impl SignatureAccumulator {
    /// Adds the given signature to the list of pending signatures or to the appropriate
    /// `SignedMessage`. Returns the message, if it has enough signatures now.
    pub fn add_proof(
        &mut self,
        msg: &RoutingMessage,
        pk_share: BlsPublicKeyShare,
        sig: BlsSignatureShare,
        pk_set: &BlsPublicKeySet,
    ) -> Option<BlsSignature> {
        self.remove_expired();
        // TODO: hash() below also serialises the message - this could probably be optimised
        let serialised_msg = match serialise(msg) {
            Ok(serialised_msg) => serialised_msg,
            _ => {
                return None;
            }
        };
        if !pk_share.verify(&sig, serialised_msg) {
            return None;
        }
        let hash = match msg.hash() {
            Ok(hash) => hash,
            _ => {
                return None;
            }
        };
        if let Some(entry) = self.msgs.get_mut(&hash) {
            let _ = entry.shares.insert(pk_share, sig);
        } else {
            let mut entry = AccumulatorEntry {
                shares: HashMap::new(),
                timestamp: Instant::now(),
            };
            let _ = entry.shares.insert(pk_share, sig);
            let _ = self.msgs.insert(hash, entry);
        }
        self.remove_if_complete(&hash, pk_set)
    }

    fn remove_expired(&mut self) {
        let expired_msgs = self
            .msgs
            .iter()
            .filter(|(_, entry)| entry.timestamp.elapsed() > ACCUMULATION_TIMEOUT)
            .map(|(hash, _)| *hash)
            .collect_vec();
        for hash in expired_msgs {
            let _ = self.msgs.remove(&hash);
        }
    }

    fn remove_if_complete(
        &mut self,
        hash: &Digest256,
        pk_set: &BlsPublicKeySet,
    ) -> Option<BlsSignature> {
        if let Some(full_sig) = self.msgs.get(hash).and_then(|entry| {
            pk_set.combine_signatures(
                entry
                    .shares
                    .iter()
                    .map(|(pk_share, sig_share)| (pk_share.clone(), sig_share)),
            )
        }) {
            let _ = self.msgs.remove(hash);
            Some(full_sig)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::SectionInfo,
        id::{FullId, PublicId},
        messages::{
            DirectMessage, MessageContent, RoutingMessage, SignedDirectMessage,
            SignedRoutingMessage,
        },
        routing_table::{Authority, Prefix},
        types::MessageId,
    };
    use itertools::Itertools;
    use rand;
    use std::collections::BTreeSet;
    use unwrap::unwrap;

    struct MessageAndSignatures {
        signed_msg: SignedRoutingMessage,
        signature_msgs: Vec<SignedDirectMessage>,
    }

    impl MessageAndSignatures {
        fn new<'a, I>(
            msg_sender_id: &FullId,
            other_ids: I,
            all_ids: BTreeSet<PublicId>,
        ) -> MessageAndSignatures
        where
            I: Iterator<Item = &'a FullId>,
        {
            let routing_msg = RoutingMessage {
                src: Authority::ClientManager(rand::random()),
                dst: Authority::ClientManager(rand::random()),
                content: MessageContent::Relocate {
                    message_id: MessageId::new(),
                },
            };
            let prefix = Prefix::new(0, *unwrap!(all_ids.iter().next()).name());
            let sec_info = unwrap!(SectionInfo::new(all_ids, prefix, None));
            let signed_msg = unwrap!(SignedRoutingMessage::new(
                routing_msg.clone(),
                sec_info.clone()
            ));
            let signature_msgs = other_ids
                .map(|_id| {
                    unwrap!(SignedDirectMessage::new(
                        DirectMessage::MessageSignature(unwrap!(SignedRoutingMessage::new(
                            routing_msg.clone(),
                            sec_info.clone(),
                        ))),
                        msg_sender_id,
                    ))
                })
                .collect();

            MessageAndSignatures {
                signed_msg,
                signature_msgs,
            }
        }
    }

    struct Env {
        msgs_and_sigs: Vec<MessageAndSignatures>,
    }

    impl Env {
        fn new() -> Env {
            let msg_sender_id = FullId::new();
            let mut pub_ids = vec![*msg_sender_id.public_id()]
                .into_iter()
                .collect::<BTreeSet<_>>();
            let mut other_ids = vec![];
            for _ in 0..8 {
                let full_id = FullId::new();
                let _ = pub_ids.insert(*full_id.public_id());
                other_ids.push(full_id);
            }
            let msgs_and_sigs = (0..5)
                .map(|_| {
                    MessageAndSignatures::new(&msg_sender_id, other_ids.iter(), pub_ids.clone())
                })
                .collect();
            Env {
                msgs_and_sigs: msgs_and_sigs,
            }
        }
    }

    #[test]
    fn section_src_add_signature_last() {
        use fake_clock::FakeClock;

        let mut sig_accumulator = SignatureAccumulator::default();
        let env = Env::new();

        // Add each message with the section list added - none should accumulate.
        env.msgs_and_sigs.iter().foreach(|msg_and_sigs| {
            let signed_msg = msg_and_sigs.signed_msg.clone();
            let result = sig_accumulator.add_proof(signed_msg);
            assert!(result.is_none());
        });
        let expected_msgs_count = env.msgs_and_sigs.len();
        assert_eq!(sig_accumulator.msgs.len(), expected_msgs_count);

        // Add each message's signatures - each should accumulate once quorum has been reached.
        env.msgs_and_sigs.iter().foreach(|msg_and_sigs| {
            msg_and_sigs.signature_msgs.iter().foreach(|signature_msg| {
                let old_num_msgs = sig_accumulator.msgs.len();

                let result = match signature_msg.content() {
                    DirectMessage::MessageSignature(msg) => sig_accumulator.add_proof(msg.clone()),
                    ref unexpected_msg => panic!("Unexpected message: {:?}", unexpected_msg),
                };

                if let Some(returned_msg) = result {
                    assert_eq!(sig_accumulator.msgs.len(), old_num_msgs - 1);
                    assert_eq!(
                        msg_and_sigs.signed_msg.routing_message(),
                        returned_msg.routing_message()
                    );
                    unwrap!(returned_msg.check_integrity());
                }
            });
        });

        FakeClock::advance_time(ACCUMULATION_TIMEOUT.as_secs() * 1000 + 1000);

        sig_accumulator.remove_expired();
        assert!(sig_accumulator.msgs.is_empty());
    }
}
