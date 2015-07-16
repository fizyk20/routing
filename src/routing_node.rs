// Copyright 2015 MaidSafe.net limited.
//
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use cbor::{CborError};
use rand;
use sodiumoxide;
use std::sync::mpsc;
use std::boxed::Box;
use std::thread;
use std::marker::PhantomData;

use crust;
use NameType;
use node_interface::{Interface, CreatePersonas};
use routing_membrane::RoutingMembrane;
use id::Id;
use public_id::PublicId;
use types::{MessageId, SourceAddress, DestinationAddress};
use utils::{encode, decode};
use authority::{Authority};
use messages::{RoutingMessage, SignedMessage, MessageType, ConnectRequest};
use error::{RoutingError};
use std::thread::spawn;

type ConnectionManager = crust::ConnectionManager;
type Event = crust::Event;
pub type Endpoint = crust::Endpoint;
type PortAndProtocol = crust::Port;

type RoutingResult = Result<(), RoutingError>;

/// DHT node
pub struct RoutingNode<F, G> where F : Interface + 'static,
                                   G : CreatePersonas<F> {
    genesis: Box<G>,
    phantom_data: PhantomData<F>,
    id: Id,
    own_name: NameType,
    next_message_id: MessageId,
    bootstrap: Option<(Endpoint, Option<NameType>)>,
}

impl<F, G> RoutingNode<F, G> where F : Interface + 'static,
                                   G : CreatePersonas<F> {
    pub fn new(genesis: G) -> RoutingNode<F, G> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)
        let id = Id::new();
        let own_name = id.get_name();
        RoutingNode { genesis: Box::new(genesis),
                      phantom_data: PhantomData,
                      id : id,
                      own_name : own_name.clone(),
                      next_message_id: rand::random::<MessageId>(),
                      bootstrap: None,
                    }
    }

    /// Starts a node without requiring responses from the network.
    /// Starts the routing membrane without looking to bootstrap.
    /// It will relocate its own address with the hash of twice its name.
    /// This allows the network to later reject this zero node
    /// when the routing_table is full.
    ///
    /// A zero_membrane will not be able to connect to an existing network,
    /// and as a special node, it will be rejected by the network later on.
    pub fn run_zero_membrane(&mut self) {
        // This code is currently refactored by Ben, but I'm getting
        // compilation errors so I'm commenting it temporarily.
        unimplemented!()
        //let (event_output, event_input) = mpsc::channel();
        //let mut cm = crust::ConnectionManager::new(event_output);
        //// TODO: Default Protocol and Port need to be passed down
        //let ports_and_protocols : Vec<PortAndProtocol> = Vec::new();
        //// TODO: Beacon port should be passed down
        //let beacon_port = Some(5483u16);
        //let listeners = match cm.start_listening2(ports_and_protocols, beacon_port) {
        //    Err(reason) => {
        //        println!("Failed to start listening: {:?}", reason);
        //        (vec![], None)
        //    }
        //    Ok(listeners_and_beacon) => listeners_and_beacon
        //};
        //let self_relocated_name = utils::calculate_self_relocated_name(
        //    &self.id.get_crypto_public_sign_key(),
        //    &self.id.get_crypto_public_key(),
        //    &self.id.get_validation_token());
        //println!("ZERO listening on {:?}, named {:?}", listeners.0.first(),
        //    self_relocated_name);
        //self.id.assign_relocated_name(self_relocated_name);

        //let mut membrane = RoutingMembrane::<F>::new(
        //    cm, event_input, None,
        //    listeners.0, self.id.clone(),
        //    self.genesis.create_personas());
        //// TODO: currently terminated by main, should be signalable to terminate
        //// and join the routing_node thread.
        //spawn(move || membrane.run());
    }

    /// Bootstrap the node to an existing (or zero) node on the network.
    /// If a bootstrap list is provided those will be used over the beacon support from CRUST.
    /// Spawns a new thread and moves a newly constructed Membrane into this thread.
    /// Routing node uses the genesis object to create a new instance of the personas to embed
    /// inside the membrane.
    //  TODO: a (two-way) channel should be passed in to control the membrane.
    pub fn bootstrap(&mut self, bootstrap_list: Option<Vec<Endpoint>>)
            -> Result<(), RoutingError>  {

        let (event_output, event_input) = mpsc::channel();
        let mut cm = crust::ConnectionManager::new(event_output);
        // TODO: Default Protocol and Port need to be passed down
        let ports_and_protocols : Vec<PortAndProtocol> = Vec::new();
        // TODO: Beacon port should be passed down
        let beacon_port = Some(5483u16);
        let listeners = match cm.start_listening2(ports_and_protocols, beacon_port) {
            Err(reason) => {
                println!("Failed to start listening: {:?}", reason);
                (vec![], None)
            }
            Ok(listeners_and_beacon) => listeners_and_beacon
        };

        // CRUST bootstrap
        let bootstrapped_to = try!(cm.bootstrap(bootstrap_list, beacon_port)
            .map_err(|_|RoutingError::FailedToBootstrap));
        println!("BOOTSTRAP to {:?}", bootstrapped_to);
        println!("NODE listening on {:?}", listeners.0.first());
        self.bootstrap = Some((bootstrapped_to.clone(), None));
        cm.connect(vec![bootstrapped_to.clone()]);
        // allow CRUST to connect
        thread::sleep_ms(100);

        let unrelocated_id = self.id.clone();
        let relocated_name : Option<NameType>;

        // FIXME: connect request should not require the knowledge of the name you're connecting to
        let connect_msg = match self.construct_connect_request_msg(&unrelocated_id.get_name(),
                                   listeners.0.clone()) {
            Ok(msg)  => msg,
            Err(err) => return Err(RoutingError::Cbor(err)),
        };

        let serialised_message = try!(encode(&connect_msg));

        ignore(cm.send(bootstrapped_to.clone(), serialised_message));

        // FIXME: for now just write out explicitly in this function the bootstrapping loop
        // - fully check match of returned public id with ours
        // - break from loop if unsuccessful; no response; retry
        // - this initial bootstrap should only use the WhoAreYou paradigm,
        //   not the unknown_connect_request as currently used.
        println!("Waiting for responses from network");
        loop {
            match event_input.recv() {
                Err(_) => {},
                Ok(crust::Event::NewMessage(source_endpoint, bytes)) => {
                    match decode::<RoutingMessage>(&bytes) {
                        Ok(message) => {
                            match message.message_type {
                                MessageType::ConnectResponse(connect_response) => {
                                    println!("Received connect response");

                                    let put_public_id_msg
                                        = try!(self.construct_put_public_id_msg(
                                                        &PublicId::new(&unrelocated_id)));

                                    let serialised_message = try!(encode(&put_public_id_msg));

                                    // Store the NameType of the bootstrap node.
                                    self.bootstrap = self.bootstrap.clone().map(|(ep, name)| {
                                            if ep == source_endpoint {
                                                (ep, Some(connect_response.receiver_id))
                                            }
                                            else {
                                                (ep, name)
                                            }
                                        });

                                    ignore(cm.send(bootstrapped_to.clone(), serialised_message));
                                },
                                MessageType::PutPublicIdResponse(public_id) => {
                                    relocated_name = Some(public_id.name());
                                    debug_assert!(public_id.is_relocated());
                                    //if public_id.validation_token
                                    //        != self.id.get_validation_token() {
                                    //    return Err(RoutingError::FailedToBootstrap);
                                    //}
                                    println!("Received PutPublicId relocated name {:?} from {:?}",
                                        relocated_name, self.id.get_name());
                                    break;
                                },
                                _ => {
                                    println!("Received unexpected message {:?}",
                                        message.message_type);
                                }
                            }
                        },
                        Err(_) => {
                          // WhoAreYou/IAm messages fall in here.
                        }
                    };
                },
                Ok(crust::Event::NewConnection(endpoint)) => {
                    println!("NewConnection on {:?} while waiting on network.", endpoint);
                },
                Ok(crust::Event::LostConnection(_)) => {
                    return Err(RoutingError::FailedToBootstrap);
                }
            }
        };

        match (relocated_name, self.bootstrap.clone()) {
            // This means that we have been relocated, we know our bootstrap
            // endpoint and we also know the name of the bootstrap node.
            (Some(relocated_name), Some((bootstrap_ep, Some(bootstrap_name)))) => {
                self.id.assign_relocated_name(relocated_name);
                debug_assert!(self.id.is_relocated());

                let mut membrane = RoutingMembrane::<F>::new(
                    cm,
                    event_input,
                    Some((bootstrap_ep, bootstrap_name)),
                    listeners.0,
                    self.id.clone(),
                    self.genesis.create_personas());

                spawn(move || membrane.run());
            },
            _ => panic!("DEBUG: failed to bootstrap or did not relocate the publicId.")
        };
        Ok(())
    }

    fn construct_connect_request_msg(&mut self, destination: &NameType,
            accepting_on: Vec<Endpoint>) -> Result<SignedMessage, CborError> {
        let message_id = self.get_next_message_id();

        let connect_request = ConnectRequest {
            local_endpoints    : accepting_on,
            external_endpoints : vec![],
            requester_id       : self.own_name.clone(),
            receiver_id        : destination.clone(),
            requester_fob      : PublicId::new(&self.id),
        };

        let message =  RoutingMessage {
            destination  : DestinationAddress::Direct(destination.clone()),
            source       : SourceAddress::RelayedForNode(self.id.get_name(), self.id.get_name()),
            orig_message : None,
            message_type : MessageType::ConnectRequest(connect_request),
            message_id   : message_id.clone(),
            authority    : Authority::ManagedNode,
        };

        SignedMessage::new(&message, self.id.signing_private_key())
    }

    fn construct_put_public_id_msg(&mut self, our_unrelocated_id: &PublicId)
            -> Result<SignedMessage, CborError> {

        let message_id = self.get_next_message_id();

        let message =  RoutingMessage {
            destination  : DestinationAddress::Direct(our_unrelocated_id.name()),
            source       : SourceAddress::RelayedForNode(self.id.get_name(), self.id.get_name()),
            orig_message : None,
            message_type : MessageType::PutPublicId(our_unrelocated_id.clone()),
            message_id   : message_id.clone(),
            authority    : Authority::ManagedNode,
        };

        SignedMessage::new(&message, self.id.signing_private_key())
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let temp = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        return temp;
    }
}

fn ignore<R,E>(_: Result<R,E>) {}

#[cfg(test)]
mod test {

}
