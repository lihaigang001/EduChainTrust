# SPDX-License-Identifier: MIT
import streamlit as st
from educhaintrust.identity.did import DIDManager
from educhaintrust.credential.vc import VerifiableCredential
from educhaintrust.credential.signing import Ed25519CredentialSigner
from educhaintrust.privacy.hashing import generate_hash
from educhaintrust.blockchain.mockchain import MockBlockchain
from educhaintrust.verifier.engine import VerificationEngine
from educhaintrust.analytics.evidence import EvidenceScore

st.set_page_config(page_title="EduChainTrust",layout="wide")
st.title("EduChainTrust Dashboard")
st.caption("Local synthetic research demonstration; session keys and evidence are not a real university authority")
if "chain" not in st.session_state: st.session_state.chain=MockBlockchain()
if "keys" not in st.session_state: st.session_state.keys=Ed25519CredentialSigner.generate_keypair()
if "credential" not in st.session_state: st.session_state.credential=None
if "tx" not in st.session_state: st.session_state.tx=None
with st.form("credential"):
    name=st.text_input("Learner name","Alice")
    institution=st.text_input("Institution","University-A")
    course=st.text_input("Course","Artificial Intelligence")
    go=st.form_submit_button("Create and anchor credential")
if go:
    ident=DIDManager().create_identity("student",name,institution)
    unsigned=VerifiableCredential.create(institution,ident["did"],{"course":course})
    cred=Ed25519CredentialSigner.sign(unsigned,st.session_state.keys[0])
    tx=st.session_state.chain.anchor(generate_hash(cred),institution)
    st.session_state.credential,st.session_state.tx=cred,tx
if st.session_state.credential:
    st.json(st.session_state.credential); st.write("Evidence transaction:",st.session_state.tx)
    if st.button("Verify credential"):
        trust={st.session_state.credential["issuer"]:{"public_key":st.session_state.keys[1],"verification_method":"urn:educhaintrust:key:issuer"}}
        st.json(VerificationEngine().verify(st.session_state.credential,st.session_state.chain,st.session_state.tx,trust))
    if st.button("Revoke local evidence"):
        st.session_state.chain.revoke(st.session_state.tx,"local-demo")
        st.write("Status:",st.session_state.chain.status(st.session_state.tx))
st.subheader("Learning evidence score")
vals=[st.slider(k,0.0,1.0,v,0.05) for k,v in [("Completion",.8),("Assessment",.9),("Time",.7),("Interaction",.6)]]
st.metric("Evidence score",f"{EvidenceScore.calculate(*vals):.3f}")
