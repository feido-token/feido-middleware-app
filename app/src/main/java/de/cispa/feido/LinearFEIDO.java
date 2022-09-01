package de.cispa.feido;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.nfc.Tag;
import android.os.AsyncTask;
import android.os.Build;

import logoverwrite.Log;

import android.preference.PreferenceManager;
import android.widget.CheckBox;
import android.widget.EditText;

import androidx.annotation.RequiresApi;
import androidx.core.util.Pair;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;

import org.bouncycastle.jce.ECPointUtil;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.Util;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG1File;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.cryptodotcom.*;
import com.cryptodotcom.types.*;

import javax.crypto.interfaces.DHPublicKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import org.apache.commons.codec.binary.Hex;
import org.jmrtd.protocol.EACCAAPDUSender;
import org.jmrtd.protocol.EACCAProtocol;
import org.json.JSONException;
import org.json.JSONObject;

import de.anon.fidosgx.protos.AE_TAChallengeReq;
import de.anon.fidosgx.protos.AE_TAChallengeResp;
import de.anon.fidosgx.protos.CAInit;
import de.anon.fidosgx.protos.CAInitReply;
import de.anon.fidosgx.protos.FidoLogin;
import de.anon.fidosgx.protos.FidoRegister;
import de.anon.fidosgx.protos.FidoRequest;
import de.anon.fidosgx.protos.FidoResponse;
import de.anon.fidosgx.protos.KeySpecs;

/**
 * Storage object passed along the call chain of the entire LinearFEIDO process.
 * Functions may add values or access previously set ones.
 */
class StateBasket{
    /**
     * Initializes a stateBasket for FEIDO.
     * @param tag An NFC Tag
     * @param paceKey A PACE key for use with an ePassport
     * @param iasRootStream The certificate used for communication with the SGX Enclave
     * @param context AppContext used for caching
     */
    public StateBasket(Tag tag, PACEKeySpec paceKey, InputStream iasRootStream, Context context){
        this.tag = tag;
        this.paceKey = paceKey;
        this.iasRootStream = iasRootStream;
        this.context = context;
        String TAG = this.getClass().getSimpleName();
        Log.i(TAG, "Initialized stateBasket with paceKey:" +  paceKey.toString());
    }

    public final Tag tag;
    public final PACEKeySpec paceKey;
    public final InputStream iasRootStream;   // for reading in the Intel Attestation Service root certificate

    public final Context context;

    public final int webSocketServerPort = 11111;     // websocket server port to listen for browser extension
    public WebSocketServer clientCommunicationWebsocketServer;  // resp. websocket server object
    public EIDInterface eidInterface;
    public FEIDOProto.FEIDOWrapper feidoRequest;

    public final String SGXIP = "192.168.178.45"; // IP of Enclave (for RA-TLS)
    public final int SGXPort = 4433;          // TCP port of Enclave (for RA-TLS)
    public SSLContext ctx;              // SSL context of RA-TLS connection
    public SSLSocket SGXRawSocket;      // RA-TLS socket from Client to Enclave
    public InputStream SGXSocketIn;     // InputStream (receive) of RA-TLS
    public OutputStream SGXSocketOut;   // OutputStream (send) of RA-TLS

    public SODFile sodFile;     // Document Security Object read from ePassport
    public DG1File dg1File;     // DG1 (personal data) read from ePassport
    public DG14File dg14File;   // DG14 (security infos) read from ePassport

    public JSONObject collectedClientData;

    public String caOID;        // enclave-selected CA cipher OID
    public int caKeyID;         // enclave-selected CA key ID
    public ByteString PKSGX;    // CA public key of Enclave

    public ByteString sgxChallenge;
    public ByteString passportChallenge;
    public FEIDOProto.FEIDOWrapper feidoResponse;
}

/**
 * Simple linear implementation of FEIDO.
 * All steps are executed in a strict order.
 * Every function calls the next function and a StateBasket is passed along the entire call chain
 * to transfer values to later parts of the chain.
 */
public class LinearFEIDO extends AsyncTask<StateBasket, Pair<String, StateBasket>, Void> {

    private final String TAG = this.getClass().getSimpleName();
    private final List<Pair<String, Long>> timeMeasurement = new ArrayList<>();

    /**
     * Start the FEIDO call chain - called via .execute(...)
     * @param stateBaskets An initialized stateBasket to start the chain.
     */
    @Override
    protected Void doInBackground(StateBasket... stateBaskets) {
        Log.i(TAG, "Starting FEIDO call chain.");
        publishProgress(new Pair<>("Starting FEIDO call chain.", stateBaskets[0]));

        listenForFIDORequestFromClient(stateBaskets[0]);
        return null;
    }

    /**
     * Update UI and logging with progress updates during the LinearFEIDO call chain.
     * @param pairs A pair of (String, Statebasket)
     */
    @Override
    protected void onProgressUpdate(Pair... pairs) {
        Activity activity = (Activity) ((StateBasket) pairs[0].second).context;
        EditText outField = activity.findViewById(R.id.editTextOutput);

        if (timeMeasurement.size() == 0){
            outField.setText("");
        }

        long t1 = System.nanoTime();
        timeMeasurement.add(new Pair<>(pairs[0].first.toString(), t1));

        if (timeMeasurement.size() > 1){
            long t0 = timeMeasurement.get(timeMeasurement.size() - 2).second;
            Log.d("TIME", pairs[0].first + " Elapsed ms: " + (t1 - t0) / 1000000);
            outField.append((String) pairs[0].first + " elapsed: " + (t1 - t0) / 1000000 + "ms" + "\n");
        }
        else {
            Log.d("TIME", pairs[0].first + " First measurement");
            outField.append((String) pairs[0].first + "\n");
        }

        SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(activity);
        if (sharedPref.getBoolean("cardAccessFileCached", false)){
            ((CheckBox) activity.findViewById(R.id.checkBox3)).setChecked(true);
        }
    }

    /**
     * Start a WebSocket server and listen for an FEIDO Request from the client.
     * The port can be configured in the stateBasket.
     * @param st The stateBasket passed along the call chain.
     */
    public void listenForFIDORequestFromClient(StateBasket st){
        publishProgress(new Pair<>("Beginning listenForFIDORequestFromClient", st));
        class ClientCommunicationWebsocketServer extends WebSocketServer {
            ClientCommunicationWebsocketServer(int port){
                super(new InetSocketAddress(port));
            }

            @Override
            public void onOpen(WebSocket conn, ClientHandshake handshake) {
                Log.i(TAG, "New connection from: " + conn.getRemoteSocketAddress().getAddress().getHostAddress());
            }

            @Override
            public void onClose(WebSocket conn, int code, String reason, boolean remote) {
                Log.i(TAG, "Closed connection from: " + conn.getRemoteSocketAddress().getAddress().getHostAddress());
                try {
                    this.stop(1000);
                } catch (InterruptedException e) {
                    Log.e(TAG, "Failed to stop WebSocketServer!");
                    Log.e(TAG, e.getMessage());
                }
            }

            @Override
            public void onMessage(WebSocket conn, String message) {
            }

            @RequiresApi(api = Build.VERSION_CODES.O)
            @Override
            public void onMessage(WebSocket conn, ByteBuffer message) {
                Log.i(TAG, "Received following packet: " + message.toString());

                try {
                    st.feidoRequest = FEIDOProto.FEIDOWrapper.parseFrom(message.array());
                    Log.i(TAG, "Parsed following packet: " + st.feidoRequest.toString());
                    if (st.feidoRequest == null){
                        throw new InvalidProtocolBufferException("Message could not be parsed!");
                    }
                } catch (InvalidProtocolBufferException e) {
                    Log.e(TAG, "Error parsing FIDO request from client!");
                    Log.e(TAG, e.getMessage());
                }

                publishProgress(new Pair<>("Received client request.", st));

                establishTLSConnectionWithEnclave(st);
            }

            @Override
            public void onError(WebSocket conn, Exception ex) {
                Log.e(TAG, ex.toString());
            }

            @Override
            public void onStart() {
                Log.i(TAG, "Started WebSocketServer.");
            }
        }

        st.clientCommunicationWebsocketServer =
                new ClientCommunicationWebsocketServer(st.webSocketServerPort);
        st.clientCommunicationWebsocketServer.setReuseAddr(true);
        st.clientCommunicationWebsocketServer.start();
        publishProgress(new Pair<>("Finished listenForFIDORequestFromClient", st));
    }

    /**
     * Establish an authenticated TLS connection with the SGX server.
     * IP and port can be configured in the stateBasket.
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public void establishTLSConnectionWithEnclave(StateBasket st){
        publishProgress(new Pair<>("Beginning establishTLSConnectionWithEnclave", st));
        Log.i(TAG, "Starting enclave communication channel.");

        /* 1. Create SGX verifier for TLS connection */
        Set<EnclaveQuoteStatus> validStatuses = new HashSet<>();
        validStatuses.add(EnclaveQuoteStatus.OK);
        validStatuses.add(EnclaveQuoteStatus.GROUP_OUT_OF_DATE);

        // some test setups required this (maybe bcs. of pre-built OOT driver in one case?)
        validStatuses.add(EnclaveQuoteStatus.CONFIGURATION_NEEDED);

        // version v4
        validStatuses.add(EnclaveQuoteStatus.SW_HARDENING_NEEDED);
        validStatuses.add(EnclaveQuoteStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED);

        // here we could check if the enclave matches a certain hash / signer
        QuoteVerifier qv = new QuoteVerifier() {
            public boolean verify(Quote quote) {
                System.out.println("MRENCLAVE = " + Hex.encodeHexString(quote.report_body.mr_enclave) + "\nMRSIGNER = " + Hex.encodeHexString(quote.report_body.mr_signer));
                // does nothing
                return true;
            }
        };

        try {
        EnclaveCertVerifier ecv = new EnclaveCertVerifier(validStatuses, qv, Duration.ofSeconds(86400), st.iasRootStream);

        /* 2. Create an SSL context with the SGX-aware verifier */
        st.ctx = SSLContext.getInstance("TLS");
        st.ctx.init(null, new TrustManager[] {ecv}, null);
        Log.i(TAG, "Initialized authenticated TLS connection with Enclave/SGX Sever.");

        publishProgress(new Pair<>("Finished establishTLSConnectionWithEnclave", st));

        establishPACEWithPassport(st);
        }
        catch (CertificateException | NoSuchAlgorithmException | KeyManagementException e){
            Log.e(TAG, "Establishing connection with enclave failed!");
            Log.e(TAG, e.getMessage());
        }
    }

    /**
     * Initialize a connection with the ePassport and run the PACE protocol.
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public void establishPACEWithPassport(StateBasket st){
        publishProgress(new Pair<>("Beginning establishPACEWithPassport", st));
        try {
            st.eidInterface = new EIDEPassportInterface(st.tag);
            Log.i(TAG, "Initialized EIDInterface for communication with ePassport.");
            st.eidInterface.runPace(st.paceKey, st.context);
            Log.i(TAG, "Successfully established PACE with ePassport.");
        } catch (CardServiceException e){
            Log.e(TAG, "Initializing EIDInterface failed!");
            Log.e(TAG, e.getMessage());
            shutdownSession(st);
            shutdownFinal(st);
        } catch (IOException e){
            Log.e(TAG, "PACE failed!");
            Log.e(TAG, e.getMessage());
        }
        Log.i(TAG, "Established PACE with passport.");

        publishProgress(new Pair<>("Finished establishPACEWithPassport", st));
        readInitialDGsFromPassport(st);
    }

    /**
     * Read the needed DataGroups from the ePassport (DG1 - MRZ, DG14 and SOD).
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public void readInitialDGsFromPassport(StateBasket st){
        publishProgress(new Pair<>("Beginning readInitialDGsFromPassport", st));
        Log.i(TAG, "Reading DataGroups from ePassport.");
        st.sodFile = st.eidInterface.readSODFile(st.context);
        Log.i(TAG, "SOD: " + st.sodFile.toString());
        st.dg1File = st.eidInterface.readDG1File(st.context);
        Log.i(TAG, "DG1: " + st.dg1File.toString());
        st.dg14File = st.eidInterface.readDG14File(st.context);
        Log.i(TAG, "DG14: " + st.dg14File.toString());
        Log.i(TAG, "Successfully read DataGroups from ePassport.");
        publishProgress(new Pair<>("Finished readInitialDGsFromPassport", st));

        sendFEIDORequestToEnclave(st);
    }

    /**
     * Forward the FEIDO request received from the client earlier to the SGX server.
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public void sendFEIDORequestToEnclave(StateBasket st) {
        publishProgress(new Pair<>("Beginning sendFEIDORequestToEnclave", st));
        /* 3. Create a client TLS socket and try to connect */
        try {
            st.SGXRawSocket = (SSLSocket) st.ctx.getSocketFactory().createSocket(st.SGXIP, st.SGXPort);
            st.SGXSocketIn = st.SGXRawSocket.getInputStream();
            st.SGXSocketOut = st.SGXRawSocket.getOutputStream();

            /* 4. Build a demo FIDO2 registration request (i.e., request that the enclave creates a new key pair) */
            // build CollectedClientData
            String type = null;
            String challenge = null;
            String origin = null;
            Boolean crossOrigin = false;
            switch (st.feidoRequest.getPacketCase()) {
                case PUBLICKEYCREDENTIALCREATIONOPTIONS:
                    type = "webauthn.create";
                    challenge = Base64.getUrlEncoder().encodeToString(st.feidoRequest
                            .getPublicKeyCredentialCreationOptions().getChallenge().toByteArray()).
                            replaceAll("=", "");
                    Log.i(TAG, "Challenge (Hex):" + bytesToHex(
                            st.feidoRequest.getPublicKeyCredentialCreationOptions().getChallenge().toByteArray()));
                    origin = st.feidoRequest.getPublicKeyCredentialCreationOptions().getOrigin();
                    break;
                case PUBLICKEYCREDENTIALREQUESTOPTIONS:
                    type = "webauthn.get";
                    challenge = Base64.getUrlEncoder().encodeToString(st.feidoRequest
                            .getPublicKeyCredentialRequestOptions().getChallenge().toByteArray()).
                            replaceAll("=", "");
                    origin = st.feidoRequest.getPublicKeyCredentialRequestOptions().getOrigin();
                    break;
                default:
                    Log.e(TAG, "Unhandled FEIDOApp protobuf message?");
                    break;
            }

            st.collectedClientData = new JSONObject();
            try {
                st.collectedClientData.put("type", type);
                st.collectedClientData.put("challenge", challenge);
                st.collectedClientData.put("origin", origin);
                st.collectedClientData.put("crossOrigin", crossOrigin);
            } catch (JSONException e){
                Log.e(TAG, "Error creating CollectedClientData");
            }
            Log.i(TAG, "Created collectedCLientData: " + st.collectedClientData.toString());

            MessageDigest messageDigest = null;
            try {
                messageDigest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e){
                Log.e(TAG, "Error initializing SHA-256!");
            }
            byte[] collectedClientDataHash = messageDigest.digest(st.collectedClientData.toString().getBytes(StandardCharsets.UTF_8));
            Log.i(TAG, "collectedCLientDataHash: " + bytesToHex(collectedClientDataHash));

            // Build FidoLogin or FidoRegister protobuf
            FidoRequest request = null;
            switch (st.feidoRequest.getPacketCase()) {
                case PUBLICKEYCREDENTIALCREATIONOPTIONS:
                    FidoRegister register = FidoRegister.newBuilder()
                            .setServiceName(st.feidoRequest.getPublicKeyCredentialCreationOptions()
                                    .getRp().getId())
                            .setSpecs(KeySpecs.newBuilder().setAlgId(st.feidoRequest
                                    .getPublicKeyCredentialCreationOptions().getPubKeyCredParams()
                                    .getAlg()))
                            .setCliDataHash(ByteString.copyFrom(collectedClientDataHash))
                            .build();
                    request = FidoRequest.newBuilder().setRegister(register).build();
                    Log.i(TAG, "Built FidoRequest.FidoReqister to send to Enclave");
                    break;

                case PUBLICKEYCREDENTIALREQUESTOPTIONS:
                    String serviceName;
                    if (st.feidoRequest.getPublicKeyCredentialRequestOptions().getRpId() != null) {
                        serviceName = st.feidoRequest.getPublicKeyCredentialRequestOptions().getRpId();
                    } else {
                        serviceName = st.feidoRequest.getPublicKeyCredentialRequestOptions().getOrigin();
                    }
                    FidoLogin login = FidoLogin.newBuilder()
                            .setServiceName(serviceName)
                            .setSpecs(KeySpecs.newBuilder().setAlgId(-7))
                            .setCliDataHash(ByteString.copyFrom(collectedClientDataHash))
                            .build();
                    request = FidoRequest.newBuilder().setLogin(login).build();
                    Log.i(TAG, "Built FidoRequest.FidoLogin to send to Enclave. Size: " + request.getSerializedSize());
                    break;

                default:
                    Log.e(TAG, "Received neither FidoRegister nor FidoLogin from client?!");
                    break;
            }

            st.SGXSocketOut.write(request.toByteArray());
            st.SGXSocketOut.flush();
            Log.i(TAG, "Successfully sent FidoRequest to Enclave.");
            publishProgress(new Pair<>("Finished sendFEIDORequestToEnclave", st));

        } catch (IOException e) {
            Log.e(TAG, "Error sending FIDO Request to SGX or error creating socket!");
            Log.e(TAG, e.getMessage());
        }

        sendPassportDGsAndPKTOEnclave(st);
    }

    // src: https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Forward the previously read DataGroups of the ePassport to the SGX server.
     * @param st The stateBasket passed along the call chain.
     */
    public void sendPassportDGsAndPKTOEnclave(StateBasket st){
        publishProgress(new Pair<>("Beginning sendPassportDGsAndPKTOEnclave", st));
        PublicKey publicKey = null;
        for (SecurityInfo securityInfo: st.dg14File.getSecurityInfos()){
            if (securityInfo instanceof ChipAuthenticationPublicKeyInfo){
                publicKey = ((ChipAuthenticationPublicKeyInfo) securityInfo).getSubjectPublicKey();
                Log.i(TAG, "Successfully found and parsed ePassport PK from DG14.");
                break;
            }
        }

        if (publicKey == null){
            Log.e(TAG, "Failed to parse ePassport PK from DG14!");
        }

        CAInit.DataGroup dg1 = CAInit.DataGroup.newBuilder()
                .setGroupData(ByteString.copyFrom(st.dg1File.getEncoded()))
                .build();

        CAInit.DataGroup dg14 = CAInit.DataGroup.newBuilder()
                .setGroupData(ByteString.copyFrom(st.dg14File.getEncoded()))
                .build();

        if (st.sodFile.getDocSigningCertificate() == null) {
            Log.d(TAG, "No embedded doc signing certificate");
        } else {
            Log.d(TAG, "Embedded doc signing certificate exists");
        }

        Log.i(TAG, "DG14 getEncoded length: " + st.dg14File.getEncoded().length);

        Log.i(TAG, "DG1: " + bytesToHex(dg1.getGroupData().toByteArray()));
        Log.i(TAG, "DG14: " + bytesToHex(dg14.getGroupData().toByteArray()));

        // Check for certificates
        if (st.sodFile.getDocSigningCertificate() == null) {
            Log.i(TAG, "getDocSigningCertificate(): null");
        } else {
            Log.i(TAG, "getDocSigningCertificate(): EXISTS");
        }

        // Check for LDS version (1.8? 1.7?)
        if (st.sodFile.getLDSVersion() == null) {
            Log.i(TAG, "no LDS version, i.e., either LDS parsing fails, or < 1.8");
        } else {
            Log.i(TAG, "LDS version: " + st.sodFile.getLDSVersion());
        }

        Log.i(TAG, "LDS digest: " + st.sodFile.getDigestAlgorithm());

        CAInit caInit = CAInit.newBuilder()
                //.setEpassPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setDocumentSecurityObject(ByteString.copyFrom(st.sodFile.getEncoded()))
                .putDataGroups(1, dg1)
                .putDataGroups(14, dg14)
                .build();

        Log.i(TAG, bytesToHex(st.sodFile.getEncoded()));
        Log.i(TAG, "Built CAInit messge to send to Enclave/SGX Server: " + caInit.toString());
        Log.i(TAG, "CAInit size: " + caInit.getSerializedSize());

        try {
            st.SGXSocketOut.write(caInit.toByteArray());
            st.SGXSocketOut.flush();
            Log.i(TAG, "Successfully sent CAInit to Enclave.");
            publishProgress(new Pair<>("Finished sendPassportDGsAndPKTOEnclave", st));
        }
        catch (IOException e){
            Log.e(TAG, "Error sending DGs and PK to SGX!");
            Log.e(TAG, e.getMessage());
        }

        listenForEnclavePK(st);
    }

    /**
     * Listen for the SGX servers PK on the authenticated TLS connection.
     * @param st The stateBasket passed along the call chain.
     */
    public void listenForEnclavePK(StateBasket st){
        publishProgress(new Pair<>("Beginning listenForEnclavePK", st));
        byte[] caInitReplyBytes = new byte[4096];
        int len = 0;
        try {
            len = st.SGXSocketIn.read(caInitReplyBytes);
            Log.i(TAG, "Read " + len + " bytes from Enclave.");
        }
        catch (IOException e) {
            Log.e(TAG, "Error on receiving data from SGX Server!");
            Log.e(TAG, e.getMessage());
        }
        if (len <= 0) {
            Log.e(TAG, "No data received from SGX Server!");
        }

        try {
            CAInitReply caInitReply = CAInitReply.parseFrom(
                    ByteString.copyFrom(caInitReplyBytes, 0, len));
            if(caInitReply == null){
                Log.e(TAG, "Error parsing CAInitReply!");
            }
            Log.i(TAG, "Parsed CAInitReply received from Enclave/SGX Server.");

            st.caOID = caInitReply.getCaCipherOidTxt();
            st.caKeyID = caInitReply.getEpassKeyId();
            st.PKSGX = caInitReply.getEphmEnclavePublicKey();

            publishProgress(new Pair<>("Finished listenForEnclavePK", st));

            sendEnclavePKToPassport(st);
        }
        catch (InvalidProtocolBufferException e){
            Log.e(TAG, "Error parsing CAInitReply!");
            Log.e(TAG, e.getMessage());
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            Log.e(TAG, "Error decoding PublicKey!");
            Log.e(TAG, e.getMessage());
        }

    }

    /**
     * Forward the previously received SGX servers PK to the ePassport.
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void sendEnclavePKToPassport(StateBasket st)
            throws RuntimeException, NoSuchAlgorithmException, InvalidKeySpecException {
        publishProgress(new Pair<>("Beginning sendEnclavePKToPassport", st));

        PublicKey epassPK = null;
        PublicKey enclavePK;

        List<ChipAuthenticationPublicKeyInfo> listInfo = st.dg14File.getChipAuthenticationPublicKeyInfos();
        for (ChipAuthenticationPublicKeyInfo caPkInfo : listInfo) {
            // we are only interested in the info for our key
            if (caPkInfo.getKeyId().intValue() != st.caKeyID) continue;
            epassPK = caPkInfo.getSubjectPublicKey();
        }
        if (epassPK == null) throw new RuntimeException("Failed finding given KeyID information");

        /* Error: The BC provider no longer provides an implementation for KeyFactory.EC.
         * see: https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html
         *
         * KeyFactory kf = KeyFactory.getInstance(epassPK.getAlgorithm(), "BC");
         */
        KeyFactory kf = KeyFactory.getInstance(epassPK.getAlgorithm());

        if (epassPK instanceof ECPublicKey) {
            //kspec = kf.getKeySpec(epassPK, DSAPublicKeySpec.class);
            ECParameterSpec params = ((ECPublicKey) epassPK).getParams();
            ECPoint point = ECPointUtil.decodePoint(params.getCurve(), st.PKSGX.toByteArray());
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
            enclavePK = kf.generatePublic(pubKeySpec);

            /* Try to make it BouncyCastle (as "BC" for KeyFactory is gone in Android ...),
             * because it always was an incompatible OpenSSLECPublicKey */
            enclavePK = Util.reconstructPublicKey(enclavePK);

        } else if (epassPK instanceof DHPublicKey) {
            throw new RuntimeException("Unexpected DH public key (not implemented yet)");
        } else {
            throw new RuntimeException("Unexpected public key type");
        }

        EACCAAPDUSender eaccaapduSender = new EACCAAPDUSender(st.eidInterface.passportService);
        try {
            EACCAProtocol.sendPublicKey(eaccaapduSender,
                    st.eidInterface.passportService.getWrapper(),
                    st.caOID,
                    BigInteger.valueOf(st.caKeyID),
                    enclavePK);
            Log.i(TAG, "Successfully sent Enclave/SGX PK to ePassport.");

            publishProgress(new Pair<>("Finished sendEnclavePKToPassport", st));

            listenForEnclaveChallenge(st);
        }
        catch (CardServiceException e) {
            Log.e(TAG, "Error sending SGX PK to Passport!");
            Log.e(TAG, e.getMessage());
        }
    }

    /**
     * Listen for the SGX servers TA_Challenge Request on the authenticated TLS connection.
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void listenForEnclaveChallenge(StateBasket st){
        publishProgress(new Pair<>("Beginning listenForEnclaveChallenge", st));
        byte[] sgxChallenge = new byte[4096];
        int len = 0;
        try {
            len = st.SGXSocketIn.read(sgxChallenge);
            Log.i(TAG, "Read " + len + " bytes from Enclave.");
        }
        catch (IOException e) {
            Log.e(TAG, "Error on receiving data from SGX Server!");
            Log.e(TAG, e.getMessage());
        }
        if (len <= 0) {
            Log.e(TAG, "No data received from SGX Server!");
        }

        try {
            AE_TAChallengeReq ae_taChallengeReq = AE_TAChallengeReq.parseFrom(
                    ByteString.copyFrom(sgxChallenge, 0, len));
            if(ae_taChallengeReq == null){
                Log.e(TAG, "Error parsing AE_TAChallengeReq!");
            }
            Log.i(TAG, "Successfully parsed AE_TAChallengeReq from SGX/Enclave.");

            publishProgress(new Pair<>("Finished listenForEnclaveChallenge", st));

            st.sgxChallenge = ae_taChallengeReq.getMsgBlob();

            sendEnclaveChallengeRequestToPassport(st);
        }
        catch (InvalidProtocolBufferException e){
            Log.e(TAG, "Error parsing AE_TAChallengeReq!");
            Log.e(TAG, e.getMessage());
        }
    }

    /**
     * Forward the previously received TA_Challenge Request to the ePassport.
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void sendEnclaveChallengeRequestToPassport(StateBasket st){
        publishProgress(new Pair<>("Beginning sendEnclaveChallengeRequestToPassport", st));
        CommandAPDU commandAPDU = new CommandAPDU(st.sgxChallenge.toByteArray());
        try {
            Log.i(TAG, "Sending following commandAPDU to ePassport: " + commandAPDU.toString());
            ResponseAPDU responseAPDU = st.eidInterface.passportService.transmit(commandAPDU);
            Log.i(TAG, "Received following responseAPDU from ePassport: " + responseAPDU.toString());
            Log.i(TAG, "Response bytes: " + bytesToHex(responseAPDU.getBytes()));
            st.passportChallenge = ByteString.copyFrom(responseAPDU.getBytes());
            publishProgress(new Pair<>("Beginning sendEnclaveChallengeRequestToPassport", st));

            sendPassportChallengeToEnclave(st);
        }
        catch (CardServiceException e) {
            Log.e(TAG, "Error forwarding SGX Get Challenge to Passport!");
            Log.e(TAG, e.getMessage());
        }
    }

    /**
     * Forward the ePassport response to the TA_Challenge request to the SGX server.
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void sendPassportChallengeToEnclave(StateBasket st){
        publishProgress(new Pair<>("Beginning sendPassportChallengeToEnclave", st));
        AE_TAChallengeResp ae_taChallengeResp = AE_TAChallengeResp.newBuilder().
                setMsgBlob(st.passportChallenge)
                .build();
        Log.i(TAG, "Successfully built AE_TAChallengeResp: " + ae_taChallengeResp.toString());

        try {
            st.SGXSocketOut.write(ae_taChallengeResp.toByteArray());
            st.SGXSocketOut.flush();
            Log.i(TAG, "Successfully sent AE_TAChallengeResp to Enclave/SGX: " + ae_taChallengeResp);
            Log.i(TAG, "AE_TAChallengeResp size:" + ae_taChallengeResp.getSerializedSize());

            publishProgress(new Pair<>("Beginning sendPassportChallengeToEnclave", st));
            listenForFEIDOReturnFromEnclave(st);
        }
        catch (IOException e){
            Log.e(TAG, "Error sending PassPort TA Challenge Response to SGX!");
            Log.e(TAG, e.getMessage());
        }
    }

    /**
     * Listen for FEIDO return/response (containing the signature) from the SGX server on the
     * authenticated TLS connection.
     * @param st The stateBasket passed along the call chain.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void listenForFEIDOReturnFromEnclave(StateBasket st){
        publishProgress(new Pair<>("Beginning listenForFEIDOReturnFromEnclave", st));
        byte[] feidoResponse = new byte[4096];
        int len = 0;
        try {
            len = st.SGXSocketIn.read(feidoResponse);
            Log.i(TAG, "Read " + len + " bytes from Enclave.");
        }
        catch (IOException e) {
            Log.e(TAG, "Error on receiving data from SGX Server!");
            Log.e(TAG, e.getMessage());
        }
        if (len == 0) {
            Log.e(TAG, "No data received from SGX Server!");
        }

        if (len == -1) {
            Log.i(TAG, "SGX Server has closed the session, maybe the eID has been blocklisted.");
            shutdownSession(st);
            publishProgress(new Pair<>("Shut connection down and now starting re-listening", st));
            listenForFIDORequestFromClient(st);
            return;
        }

        try {
            FidoResponse fidoResponse = FidoResponse.parseFrom(
                    ByteString.copyFrom(feidoResponse, 0, len));
            if (fidoResponse.hasLogin()) {

                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                bos.write(fidoResponse.getLogin().getAd().getRpIdHash().toByteArray());

                byte[] b = {  (byte) fidoResponse.getLogin().getAd().getFlags() } ;
                bos.write(b);

                int signcount_be = fidoResponse.getLogin().getAd().getSignCountBe();
                byte [] c = {
                        (byte)(signcount_be & 0xff),
                        (byte)((signcount_be & 0xff00) >> 8),
                        (byte)((signcount_be & 0xff0000) >> 16),
                        (byte)((signcount_be & 0xff000000) >> 24)
                };
                bos.write(c);
                st.feidoResponse = FEIDOProto.FEIDOWrapper.newBuilder()
                        .setPublicKeyCredential(
                                FEIDOProto.PublicKeyCredential.newBuilder()
                                        .setRawId(fidoResponse.getLogin().getCredentialId())
                                        .setResponse(FEIDOProto.AuthenticatorResponse.newBuilder()
                                            .setAuthenticatorAssertionResponse(FEIDOProto.AuthenticatorAssertionResponse.newBuilder()
                                                 .setClientDataJSON(ByteString.copyFrom(st.collectedClientData.toString().getBytes(StandardCharsets.UTF_8)))
                                                .setAuthenticatorData(ByteString.copyFrom(bos.toByteArray()))
                                                .setSignature(fidoResponse.getLogin().getAssertionSignature())
                                                .clearUserHandle())
                                        )
                        )
                        .build();
            }

            if (fidoResponse.hasRegister()) {
                st.feidoResponse = FEIDOProto.FEIDOWrapper.newBuilder()
                        .setPublicKeyCredential(
                                FEIDOProto.PublicKeyCredential.newBuilder()
                                        .setRawId(fidoResponse.getRegister().getCredentialId())
                                        .setResponse(FEIDOProto.AuthenticatorResponse.newBuilder()
                                                .setAuthenticatorAttestationResponse(FEIDOProto.AuthenticatorAttestationResponse.newBuilder()
                                                    .setClientDataJSON(ByteString.copyFrom(st.collectedClientData.toString().getBytes(StandardCharsets.UTF_8)))
                                                    .setAttestationObject(fidoResponse.getRegister().getAttestationObject())
                                                )
                                        )
                                        .setAuthenticatorAttachment(FEIDOProto.AuthenticatorAttachment.newBuilder()
                                            .setType("cross-platform")
                                        )
                        )
                        .build();
                Log.i(TAG, "attestationObject: " +  bytesToHex(fidoResponse.getRegister().getAttestationObject().toByteArray()));
            }
            Log.i(TAG, "Successfully built FidoResponse to sent to Client.");


            publishProgress(new Pair<>("Finished listenForFEIDOReturnFromEnclave", st));
            sendFIDOResponseToClient(st);
        }
        catch (InvalidProtocolBufferException e){
            Log.e(TAG, "Error parsing FidoResponse!");
            Log.e(TAG, e.getMessage());
        } catch (IOException e) {
            Log.e(TAG, "Error parsing authData!");
            Log.e(TAG, e.getMessage());
        }
    }

    /**
     * Forward the received FEIDO return/response to the client.
     * @param st The stateBasket passed along the call chain.
     */
    public void sendFIDOResponseToClient(StateBasket st) {
        publishProgress(new Pair<>("Beginning sendFIDOResponseToClient", st));
        Log.i(TAG, "Broadcasting: " + st.feidoResponse.toString());
        st.clientCommunicationWebsocketServer.broadcast(st.feidoResponse.toByteArray());

        publishProgress(new Pair<>("Sent built FidoResponse to Client.", st));

        shutdownSession(st);
        publishProgress(new Pair<>("Finished sendFIDOResponseToClient", st));
        listenForFIDORequestFromClient(st);
    }

    /**
     * Shutdown a LinearFEIDO session (WebSocket, Enclave Connection)
     * Use after finishing/failing an authentication
     * @param st The stateBasket passed along the call chain.
     */
    public void shutdownSession(StateBasket st){
        try {
            Thread.sleep(1000);
            Log.i(TAG, "Shutting down WebSocket Server.");
            st.clientCommunicationWebsocketServer.stop(1000);
        } catch (InterruptedException e) {
            Log.e(TAG, "Error shutting down WSS!");
            Log.e(TAG, e.toString());
        }
        try {
            Log.i(TAG, "Closing Enclave connection.");
            st.SGXRawSocket.close();
            st.SGXSocketIn.close();
            st.SGXSocketOut.close();
            st.iasRootStream.reset();
        } catch (IOException e) {
            Log.e(TAG, "Error closing Enclave connection!");
            Log.e(TAG, e.getMessage());
        }

        timeMeasurement.clear();

        st.eidInterface.close();
    }

    /**
     * Shutdown the eidInterface.
     * Use when exiting the app.
     * @param st The stateBasket passed along the call chain.
     */
    public void shutdownFinal(StateBasket st){
        st.eidInterface.close();
    }

}
