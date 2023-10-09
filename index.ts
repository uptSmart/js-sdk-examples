import {
  EthStateStorage,
  CredentialRequest,
  CircuitId,
  IIdentityWallet,
  ZeroKnowledgeProofRequest,
  AuthorizationRequestMessage,
  PROTOCOL_CONSTANTS,
  AuthHandler,
  core,
  CredentialStatusType,
  W3CCredential,
  CredentialStatus,
  
} from "@uptsmart/js-sdk";

import {
  initInMemoryDataStorageAndWallets,
  initCircuitStorage,
  initProofService,
  initPackageManager,
} from "./walletSetup";

import { ethers } from "ethers";
import dotenv from "dotenv";
import { generateRequestData } from "./request";
dotenv.config();

const rhsUrl = process.env.RHS_URL as string;
const walletKey = process.env.WALLET_KEY as string;


async function createIdentity(identityWallet: IIdentityWallet) {
  const { did, credential } = await identityWallet.createIdentity({
    method: core.DidMethod.Iden3,
    blockchain: core.Blockchain.Polygon,
    networkId: core.NetworkId.Mumbai,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl,
    },
  });

  return {
    did,
    credential,
  };
}

function createKYCAgeCredential(did: core.DID) {
  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "http://47.242.107.228:3003/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: did.string(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl,
    },
  };
  return credentialRequest;
}

function createKYCAgeCredentialRequest(
  circuitId: CircuitId,
  credentialRequest: CredentialRequest
): ZeroKnowledgeProofRequest {
  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "http://47.242.107.228:3003/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        documentType: {
          $eq: 99,
        },
      },
    },
  };

  const proofReqMtp: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQueryMTPV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "http://47.242.107.228:3003/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        birthday: {
          $lt: 20020101,
        },
      },
    },
  };

  switch (circuitId) {
    case CircuitId.AtomicQuerySigV2:
      return proofReqSig;
    case CircuitId.AtomicQueryMTPV2:
      return proofReqMtp;
    default:
      return proofReqSig;
  }
}

async function identityCreation() {
  console.log("=============== key creation ===============");

  let { identityWallet } = await initInMemoryDataStorageAndWallets();
  const { did, credential } = await createIdentity(identityWallet);

  console.log("=============== did ===============");
  console.log(did.string());
  console.log("=============== Auth BJJ credential ===============");
  console.log(JSON.stringify(credential));
}

async function issueCredential() {
  console.log("=============== issue credential ===============");

  let { dataStorage, identityWallet } = await initInMemoryDataStorageAndWallets();

  const { did: userDID, credential: authBJJCredentialUser } =
    await createIdentity(identityWallet);

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await createIdentity(identityWallet);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  console.log("===============  credential ===============");
  console.log(JSON.stringify(credential));

  await dataStorage.credential.saveCredential(credential);
}

async function transitState() {
  console.log("=============== transit state ===============");

  let { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await createIdentity(identityWallet);

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await createIdentity(identityWallet);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    walletKey,
    (dataStorage.states as EthStateStorage).provider
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);
}

async function generateProofs() {
  console.log("=============== generate proofs ===============");

  let { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await createIdentity(identityWallet);

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await createIdentity(identityWallet);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    walletKey,
    (dataStorage.states as EthStateStorage).provider
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  const { proof, pub_signals } = await proofService.generateProof(
    proofReqSig,
    userDID
  );

  const sigProofOk = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQuerySigV2
  );
  console.log("valid: ", sigProofOk);

  console.log(
    "================= generate credentialAtomicMTPV2 ==================="
  );

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  console.log(credsWithIden3MTPProof);
  credentialWallet.saveAll(credsWithIden3MTPProof);

  const proofReqMtp: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQueryMTPV2,
    credentialRequest
  );

  const { proof: proofMTP } = await proofService.generateProof(
    proofReqMtp,
    userDID
  );

  console.log(JSON.stringify(proofMTP));
  const mtpProofOk = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQueryMTPV2
  );
  console.log("valid: ", mtpProofOk);

  const { proof: proof2, pub_signals: pub_signals2 } =
    await proofService.generateProof(proofReqSig, userDID);

  const sigProof2Ok = await proofService.verifyProof(
    { proof: proof2, pub_signals: pub_signals2 },
    CircuitId.AtomicQuerySigV2
  );
  console.log("valid: ", sigProof2Ok);
}

async function handleAuthRequest() {
  console.log("=============== handle auth request ===============");

  let { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await createIdentity(identityWallet);

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await createIdentity(identityWallet);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    walletKey,
    (dataStorage.states as EthStateStorage).provider
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log("=================  credential auth request ===================");

  var authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.string(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  console.log(credsWithIden3MTPProof);
  credentialWallet.saveAll(credsWithIden3MTPProof);

  var authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */
  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  let pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);
  const authResponse = await authHandler.handleAuthorizationRequest(
    userDID,
    authRawRequest
  );
  console.log(JSON.stringify(authResponse, null, 2));
}

async function handleAuthRequestWithProfiles() {
  console.log(
    "=============== handle auth request with profiles ==============="
  );

  let { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await createIdentity(identityWallet);

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await createIdentity(identityWallet);

  // credential is issued on the profile!
  const profileDID = await identityWallet.createProfile(
    userDID,
    50,
    issuerDID.string()
  );

  const credentialRequest = createKYCAgeCredential(profileDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log("=================  credential auth request ===================");
  const verifierDID =
    "did:example:123#JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw";

  var authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: verifierDID,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));

  var authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  let pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);

  const authProfile = await identityWallet.getProfileByVerifier(
    authRequest.from
  );

  // let's check that we didn't create profile for verifier
  const authProfileDID = authProfile
    ? core.DID.parse(authProfile.id)
    : await identityWallet.createProfile(userDID, 100, authRequest.from);

  const resp = await authHandler.handleAuthorizationRequest(
    authProfileDID,
    authRawRequest
  );

  console.log(resp);
}

async function handleAuthRequestNoIssuerStateTransition() {
  console.log(
    "=============== handle auth request no issuer state transition ==============="
  );

  let { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await createIdentity(identityWallet);

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await createIdentity(identityWallet);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log("=================  credential auth request ===================");

  var authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.string(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));

  var authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  let pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);
  const authHandlerRequest = await authHandler.handleAuthorizationRequest(
    userDID,
    authRawRequest
  );
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function main(choice: String) {
  switch (choice) {
    case "identityCreation":
      await identityCreation();
      break;
    case "issueCredential":
      await issueCredential();
      break;
    case "transitState":
      await transitState();
      break;
    case "generateProofs":
      await generateProofs();
      break;
    case "handleAuthRequest":
      await handleAuthRequest();
      break;
    case "handleAuthRequestWithProfiles":
      await handleAuthRequestWithProfiles();
      break;
    case "handleAuthRequestNoIssuerStateTransition":
      await handleAuthRequestNoIssuerStateTransition();
      break;
    case "generateRequestData":
      await generateRequestData();
      break;

    //xxl 01   
    // 1.通过wallet产生uptick did
    case "uptickIdentityCreation":
      await uptickIdentityCreation();
      break;
    //xxl 02  
    case "uptickIssueCredential":
        await uptickIssueCredential();
        break;
    //xxl 03
    case "uptickTransitState":
        await uptickTransitState();
        break;
    //xxl 04
    case "uptickGenerateProofsAndVerify":
        await uptickGenerateProofsAndVerify();
        break;
    default:
      // default run all
      await identityCreation();
      await issueCredential();
      await transitState();
      await generateProofs();
      await handleAuthRequest();
      await handleAuthRequestWithProfiles();
      await handleAuthRequestNoIssuerStateTransition();
      await generateRequestData();

  }
}

//xxl 01
async function uptickIdentityCreation() {
  console.log("=============== xxl 00 key creation ===============");

  let { identityWallet } = await initInMemoryDataStorageAndWallets();

  console.log("=============== xxl 01 key creation ===============");
  const { did, credential } = await uptickCreateIdentity(identityWallet);

  console.log("=============== did 02===============");
  console.log(did.string());
  console.log("=============== Auth BJJ credential ===============");
  console.log(JSON.stringify(credential));
}

//xxl 01
async function uptickCreateIdentity(identityWallet: IIdentityWallet) {

  const { did, credential } = await identityWallet.createIdentity({
    method: core.DidMethod.Iden3,
    blockchain: core.Blockchain.Uptick,
    networkId: core.NetworkId.Origin,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl,
    },
  });

  return {
    did,
    credential,
  };
}

//xxl 02
async function uptickIssueCredential() {
  console.log("=============== issue credential ===============");

  let { dataStorage, identityWallet } = await initInMemoryDataStorageAndWallets();

  const { did: userDID, credential: authBJJCredentialUser } =
    await uptickCreateIdentity(identityWallet);

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await uptickCreateIdentity(identityWallet);

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  console.log("===============  credential ===============");
  console.log(JSON.stringify(credential));

  await dataStorage.credential.saveCredential(credential);

}

let userDID = "did:iden3:uptick:origin:27f8jhRD5SY6xKe4sgwrKsZMhLZ8hxoEUM8kECjCq3"
let issuerDID = "did:iden3:uptick:origin:27ZsHrZJ7nSYXUHVWvqwPJV7p1gfM77b3N1dpjzwCG"
let credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "http://47.242.107.228:3003/core/jsonld/iden3proofs.jsonld",
    "http://47.242.107.228:3003/schemas/json-ld/kyc-v3.json-ld"
  ],
  "credentialSchema": {
    "id": "http://47.242.107.228:3003/schemas/json/KYCAgeCredential-v3.json",
    "type": "JsonSchema2023"
  },
  "credentialStatus": {
    "id": "http://localhost:3001/v1/did%3Aiden3%3Auptick%3Aorigin%3A27ZsHrZJ7nSYXUHVWvqwPJV7p1gfM77b3N1dpjzwCG/claims/revocation/status/1799102100",
    "revocationNonce": 1799102100,
    "type": "SparseMerkleTreeProof"
  },
  "credentialSubject": {
    "birthday": 19960424,
    "documentType": 2,
    "id": "did:iden3:uptick:origin:27f8jhRD5SY6xKe4sgwrKsZMhLZ8hxoEUM8kECjCq3",
    "type": "KYCAgeCredential"
  },
  "expiration": "2030-04-25T14:29:26Z",
  "id": "http://localhost:3001/v1/did:iden3:uptick:origin:27ZsHrZJ7nSYXUHVWvqwPJV7p1gfM77b3N1dpjzwCG/claims/8f58a0d9-640b-11ee-bc5f-0242ac1c0006",
  "issuanceDate": "2023-10-06T05:45:30.744776971Z",
  "issuer": "did:iden3:uptick:origin:27ZsHrZJ7nSYXUHVWvqwPJV7p1gfM77b3N1dpjzwCG",
  "proof": [
    {
      "type": "BJJSignature2021",
      "issuerData": {
        "id": "did:iden3:uptick:origin:27ZsHrZJ7nSYXUHVWvqwPJV7p1gfM77b3N1dpjzwCG",
        "state": {
          "claimsTreeRoot": "401ce9557c7c170df7e533693036033ff338865e1b041d3c3529ef3ee8858a25",
          "value": "1b1ea2b6c83b7c71b8378ccf49d759368877ef5d9313954514f984d0fda79b0b"
        },
        "authCoreClaim": "cca3371a6cb1b715004407e325bd993c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005f2274d10d5277615c743d3c4073f5ba3d16351a46461cbaaa21169450062c1416a805baa47dada919e0a28e47a5860a80f7c4c3924f3b69f8f33ea0e5e039230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "mtp": {
          "existence": true,
          "siblings": []
        },
        "credentialStatus": {
          "id": "http://localhost:3001/v1/did%3Aiden3%3Auptick%3Aorigin%3A27ZsHrZJ7nSYXUHVWvqwPJV7p1gfM77b3N1dpjzwCG/claims/revocation/status/0",
          "revocationNonce": 0,
          "type": "SparseMerkleTreeProof"
        }
      },
      "coreClaim": "e966db9bfc3680ad4b5b9ce630347d8b2a0000000000000000000000000000000142af7dd97e8ac89287ba355df18083d2213c5ed01df87b5a58e70a0a0b0e0083becb2e8d53b6eb4ed46610ac68ce8c7ac32d2c51e2b9f70ef5bcedd46d712c0000000000000000000000000000000000000000000000000000000000000000941e3c6b0000000046ef72710000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "signature": "d1fa112ac6fc19d60c889c33f34b351087f09d3aa13b0c6dffdaac8be6a5579b0c59601e8696520d28d9b95423dd3500a873df6a9384748ff8429a727409b605"
    }
  ],
  "type": [
    "VerifiableCredential",
    "KYCAgeCredential"
  ]
}

let txId = "0xc1c123c7403c6f0f127d75419cdba6727fc7f74d51cf4f1f62c9955532f24e53"

async function  uptickTransitState() {
  console.log("=============== transit state ===============");

  //create did
  let issuerDIDObj = core.DID.parse(issuerDID)
  //console.log(issuerDIDObj);

  //
  let { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  let cr = new W3CCredential();
  //@context
  cr["@context"] = credential["@context"];
  //credentialSchema
  cr.credentialSchema = credential.credentialSchema
  //credentialStatus
  console.log("credential.credentialStatus.id : ",credential.credentialStatus.id)

  const credentialStatus: CredentialStatus = {
    id: credential.credentialStatus.id,
    type: CredentialStatusType.SparseMerkleTreeProof,
    revocationNonce: credential.credentialStatus.revocationNonce
  };
  cr.credentialStatus = credentialStatus

  //credentialSubject
  cr.credentialSubject = credential.credentialSubject
  cr.expirationDate = credential.expiration
  cr.id = credential.id
  cr.issuanceDate = credential.issuanceDate
  cr.issuer = credential.issuer
  cr.proof = credential.proof
  cr.type = credential.type
  await dataStorage.credential.saveCredential(cr);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );
  const res = await identityWallet.addCredentialsToMerkleTree(
    [cr],
    issuerDIDObj
  );

  console.log("================= push states to rhs ===================");
  await identityWallet.publishStateToRHS(issuerDIDObj, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    walletKey,
    (dataStorage.states as EthStateStorage).provider
  );
  const txId = await proofService.transitState(
    issuerDIDObj,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);
}


// xxl 04
// async function uptickGenerateProofs() {
//   console.log("=============== generate proofs ===============");

//   let { dataStorage, credentialWallet, identityWallet } =
//     await initInMemoryDataStorageAndWallets();

//   const circuitStorage = await initCircuitStorage();
//   const proofService = await initProofService(
//     identityWallet,
//     credentialWallet,
//     dataStorage.states,
//     circuitStorage
//   );

//   //create did
//   let userDIDObj = core.DID.parse(userDID)
//   let issuerDIDObj = core.DID.parse(issuerDID);

//   let cr = new W3CCredential();
//   //@context
//   cr["@context"] = credential["@context"];
//   //credentialSchema
//   cr.credentialSchema = credential.credentialSchema
//   //credentialStatus
//   console.log("credential.credentialStatus.id : ",credential.credentialStatus.id)

//   const credentialStatus: CredentialStatus = {
//     id: credential.credentialStatus.id,
//     type: CredentialStatusType.SparseMerkleTreeProof,
//     revocationNonce: credential.credentialStatus.revocationNonce
//   };
//   cr.credentialStatus = credentialStatus

//   //credentialSubject
//   cr.credentialSubject = credential.credentialSubject
//   cr.expirationDate = credential.expiration
//   cr.id = credential.id
//   cr.issuanceDate = credential.issuanceDate
//   cr.issuer = credential.issuer
//   cr.proof = credential.proof
//   cr.type = credential.type
//   await dataStorage.credential.saveCredential(cr);
  
//   console.log("xxl 001 : ====");
//   const credentialRequest = createKYCAgeCredential(userDIDObj);
//   console.log("xxl 002 : #### ",credentialRequest);

//   console.log("xxl 002 : ");
//   const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
//     CircuitId.AtomicQuerySigV2,
//     credentialRequest
//   );
//   console.log("xxl 003 : ",proofReqSig);

//   const { proof, pub_signals } = await proofService.generateProof(
//     proofReqSig,
//     userDIDObj
//   );

//   console.log("xxl 004 ");
//   const sigProofOk = await proofService.verifyProof(
//     { proof, pub_signals },
//     CircuitId.AtomicQuerySigV2
//   );

//   console.log("valid: ", sigProofOk);

//   console.log(
//     "================= generate credentialAtomicMTPV2 ==================="
//   );


//   // const credsWithIden3MTPProof =
//   //   await identityWallet.generateIden3SparseMerkleTreeProof(
//   //     issuerDIDObj,
//   //     [cr],
//   //     txId
//   //   );

//   // console.log("xxl 003 : ");
//   // console.log(credsWithIden3MTPProof);
//   // credentialWallet.saveAll(credsWithIden3MTPProof);

//   const proofReqMtp: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
//     CircuitId.AtomicQueryMTPV2,
//     credentialRequest
//   );

//   const { proof: proofMTP,pub_signals: pub_signals2} = await proofService.generateProof(
//     proofReqMtp,
//     userDIDObj
//   );

//   // console.log(JSON.stringify(proofMTP));
//   // const mtpProofOk = await proofService.verifyProof(
//   //   {  proof: proofMTP,pub_signals: pub_signals2 },
//   //   CircuitId.AtomicQueryMTPV2
//   // );
//   // console.log("valid: ", mtpProofOk);

//   // const { proof: proof2, pub_signals: pub_signals2 } =
//   //   await proofService.generateProof(proofReqSig, userDID);

//   // const sigProof2Ok = await proofService.verifyProof(
//   //   { proof: proof2, pub_signals: pub_signals2 },
//   //   CircuitId.AtomicQuerySigV2
//   // );
//   // console.log("valid: ", sigProof2Ok);
// }


// async function uptickGenerateProofs() {
//   console.log("=============== generate proofs ===============");

//   let { dataStorage, credentialWallet, identityWallet } =
//     await initInMemoryDataStorageAndWallets();

//   const circuitStorage = await initCircuitStorage();
//   const proofService = await initProofService(
//     identityWallet,
//     credentialWallet,
//     dataStorage.states,
//     circuitStorage
//   );

//   const { did: userDID, credential: authBJJCredentialUser } =
//   await uptickCreateIdentity(identityWallet);
//   console.log(userDID.string());

//   // const { did: issuerDID, credential: issuerAuthBJJCredential } =
//   //   await uptickCreateIdentity(identityWallet);
//   let issuerDIDStr = "did:iden3:uptick:origin:27ZsHrZJ7nSYXUHVWvqwPJV7p1gfM77b3N1dpjzwCG"
//   let issuerDID = core.DID.parse(issuerDIDStr);
  
//   const credentialRequest = createKYCAgeCredential(userDID);

//   //TODO 
//   // const credential = await identityWallet.issueCredential(
//   //   issuerDID,
//   //   credentialRequest
//   // );


//   let cr = new W3CCredential();
//   //@context
//   cr["@context"] = credential["@context"];
//   //credentialSchema
//   cr.credentialSchema = credential.credentialSchema
//   //credentialStatus
//   console.log("credential.credentialStatus.id : ",credential.credentialStatus.id)

//   const credentialStatus: CredentialStatus = {
//     id: credential.credentialStatus.id,
//     type: CredentialStatusType.SparseMerkleTreeProof,
//     revocationNonce: credential.credentialStatus.revocationNonce
//   };
//   cr.credentialStatus = credentialStatus

//   //credentialSubject
//   cr.credentialSubject = credential.credentialSubject
//   cr.expirationDate = credential.expiration
//   cr.id = credential.id
//   cr.issuanceDate = credential.issuanceDate
//   cr.issuer = credential.issuer
//   cr.proof = credential.proof
//   cr.type = credential.type
//   await dataStorage.credential.saveCredential(cr);

//   // await dataStorage.credential.saveCredential(credential);
//   //TODO

//   console.log(
//     "================= generate Iden3SparseMerkleTreeProof ======================="
//   );

//   const res = await identityWallet.addCredentialsToMerkleTree(
//     [cr],
//     issuerDID
//   );

//   console.log("xxl res ",res);

//   console.log("================= push states to rhs ===================");

//   // await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

//   console.log("================= publish to blockchain ===================");

//   // const ethSigner = new ethers.Wallet(
//   //   walletKey,
//   //   (dataStorage.states as EthStateStorage).provider
//   // );
//   // const txId = await proofService.transitState(
//   //   issuerDID,
//   //   res.oldTreeState,
//   //   true,
//   //   dataStorage.states,
//   //   ethSigner
//   // );
//   // console.log(txId);

//   // console.log(
//   //   "================= generate credentialAtomicSigV2 ==================="
//   // );


//   const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
//     CircuitId.AtomicQuerySigV2,
//     credentialRequest
//   );

//   console.log("xxl 0001");
//   const { proof, pub_signals } = await proofService.generateProof(
//     proofReqSig,
//     userDID
//   );

//   console.log("xxl 0002");
//   const sigProofOk = await proofService.verifyProof(
//     { proof, pub_signals },
//     CircuitId.AtomicQuerySigV2
//   );
//   console.log("valid: ", sigProofOk);

//   console.log(
//     "================= generate credentialAtomicMTPV2 ==================="
//   );

//   // const credsWithIden3MTPProof =
//   //   await identityWallet.generateIden3SparseMerkleTreeProof(
//   //     issuerDID,
//   //     res.credentials,
//   //     txId
//   //   );

//   // console.log(credsWithIden3MTPProof);
//   // credentialWallet.saveAll(credsWithIden3MTPProof);

//   const proofReqMtp: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
//     CircuitId.AtomicQueryMTPV2,
//     credentialRequest
//   );

//   const { proof: proofMTP , pub_signals: pub_signals3} = await proofService.generateProof(
//     proofReqMtp,
//     userDID
//   );

//   console.log(JSON.stringify(proofMTP));
//   const mtpProofOk = await proofService.verifyProof(
//     { proof: proofMTP , pub_signals: pub_signals3 },
//     CircuitId.AtomicQueryMTPV2
//   );
//   console.log("valid: ", mtpProofOk);

//   const { proof: proof2, pub_signals: pub_signals2 } =
//     await proofService.generateProof(proofReqSig, userDID);

//   const sigProof2Ok = await proofService.verifyProof(
//     { proof: proof2, pub_signals: pub_signals2 },
//     CircuitId.AtomicQuerySigV2
//   );
//   console.log("valid: ", sigProof2Ok);
// }


// all did 
async function uptickGenerateProofsAndVerify() {
  console.log("=============== generate proofs ===============");

  let { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
  await uptickCreateIdentity(identityWallet);
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await uptickCreateIdentity(identityWallet);

  
  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishStateToRHS(issuerDID, rhsUrl);

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    walletKey,
    (dataStorage.states as EthStateStorage).provider
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log("xxl proofReqSig : ",proofReqSig);
  const { proof, pub_signals } = await proofService.generateProof(
    proofReqSig,
    userDID
  );

  const sigProofOk = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQuerySigV2
  );
  console.log("valid: ", sigProofOk);

  console.log(
    "================= generate credentialAtomicMTPV2 ==================="
  );

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  console.log("xxl credsWithIden3MTPProof : ",credsWithIden3MTPProof);
  credentialWallet.saveAll(credsWithIden3MTPProof);


  const proofReqMtp: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQueryMTPV2,
    credentialRequest
  );

  const { proof: proofMTP , pub_signals: pub_signals2} = await proofService.generateProof(
    proofReqMtp,
    userDID
  );

  console.log(JSON.stringify(proofMTP));
  const mtpProofOk = await proofService.verifyProof(
    { proof: proofMTP , pub_signals: pub_signals2 },
    CircuitId.AtomicQueryMTPV2
  );
  console.log("valid: ", mtpProofOk);

  const { proof: proof2, pub_signals: pub_signals3 } =
    await proofService.generateProof(proofReqSig, userDID);

  const sigProof2Ok = await proofService.verifyProof(
    { proof: proof2, pub_signals: pub_signals3 },
    CircuitId.AtomicQuerySigV2
  );
  console.log("valid: ", sigProof2Ok);
}


(async function () {
  const args = process.argv.slice(2);
  await main(args[0]);
})();
