package de.cispa.feido;

import static org.jmrtd.PassportService.DEFAULT_MAX_BLOCKSIZE;
import static org.jmrtd.PassportService.EF_CARD_ACCESS;
import static org.jmrtd.PassportService.EF_DG1;
import static org.jmrtd.PassportService.EF_DG14;
import static org.jmrtd.PassportService.EF_SOD;
import static org.jmrtd.PassportService.NORMAL_MAX_TRANCEIVE_LENGTH;

import android.content.Context;
import android.content.SharedPreferences;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.preference.PreferenceManager;
import logoverwrite.Log;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;

import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG1File;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

/**
 * Abstract class for electronic IDs like ePassport or German eID national ID card
 */
abstract class EIDInterface {

    private final String TAG = this.getClass().getSimpleName();
    protected PassportService passportService;

    /**
     * Initializes connection with an NFC tag
     * @param tag the NFC tag, should support IsoDep
     * @throws IllegalArgumentException
     * @throws CardServiceException
     */
    public EIDInterface(Tag tag) throws IllegalArgumentException,CardServiceException {
        if (!Arrays.asList(tag.getTechList()).contains("android.nfc.tech.IsoDep")){
            throw new IllegalArgumentException("Tag is not of type IsoDep!");
        }
        IsoDep isoDep = IsoDep.get(tag);
        CardService cardService = CardService.getInstance(isoDep);
        passportService = new PassportService(cardService, NORMAL_MAX_TRANCEIVE_LENGTH, DEFAULT_MAX_BLOCKSIZE, true, false);

        try {
            passportService.open();
        } catch (CardServiceException e) {
            Log.e(TAG, e.getMessage());
            throw e;
        }

    }

    /**
     * Runs PACE protocol with the initialized tag
     * @param paceKeySpec the PACE key, commonly made up of the MRZ data
     * @throws CardServiceException
     * @throws IOException
     */
    public void runPace(PACEKeySpec paceKeySpec, Context context) throws CardServiceException, IOException {

        // Read Card Access file to get supported protocols
        CardAccessFile cardAccessFile = readCardAccessFile(context);
        Collection<SecurityInfo> securityInfoCollection = cardAccessFile.getSecurityInfos();

        // Try with all returned PACE parameters
        try {
            for (SecurityInfo securityInfo : securityInfoCollection) {
                if (securityInfo instanceof PACEInfo) {
                    passportService.doPACE(paceKeySpec, securityInfo.getObjectIdentifier(), PACEInfo.toParameterSpec(((PACEInfo) securityInfo).getParameterId()), null);
                }
            }
        } catch (CardServiceException e){
            Log.e(TAG, "PACE failed!");
            throw e;
        }

        Log.i(TAG, "PACE successful!");
        passportService.sendSelectApplet(true);
    }

    /**
     * Read Card Access File from an eID
     * @param context App context - used for caching
     */
    public CardAccessFile readCardAccessFile(Context context) {
        SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(context);
        if (sharedPref.getBoolean("cardAccessFileCached", false)) {
            Log.i(TAG, "Accessing cached DG.");
            try {
                FileInputStream fileInputStream = context.openFileInput("cardAccessFile");
                BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
                return new CardAccessFile(bufferedInputStream);
            } catch (IOException e) {
                Log.e(TAG, "Error reading cached file!");
            }
        }
        CardAccessFile file = null;
        try {
            file = new CardAccessFile(passportService.getInputStream(EF_CARD_ACCESS));
        } catch (CardServiceException | IOException e){
            Log.e(TAG, "Error reading passport file");
        }
        try {
            FileOutputStream fileOutputStream = context.openFileOutput("cardAccessFile", Context.MODE_PRIVATE);
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
            bufferedOutputStream.write(file.getEncoded());
            bufferedOutputStream.close();
            fileOutputStream.close();
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.putBoolean("cardAccessFileCached", true);
            editor.apply();

        } catch (IOException e) {
            Log.e(TAG, "Error caching file!");
        }

        return file;
    }

    public abstract DG1File readDG1File(Context context);
    public abstract DG14File readDG14File(Context context);
    public abstract SODFile readSODFile(Context context);

    public void close(){
        this.passportService.close();
    }
}

class EIDEPassportInterface extends EIDInterface {

    private static final String TAG = MainActivity.class.getSimpleName();

    /**
     * Initializes connection with an NFC tag
     *
     * @param tag the NFC tag, should support IsoDep
     * @throws IllegalArgumentException
     * @throws CardServiceException
     */
    public EIDEPassportInterface (Tag tag) throws IllegalArgumentException, CardServiceException {
        super(tag);
    }

    /**
     * Read DG1 File from an eID
     * @param context App context - used for caching
     */
    public DG1File readDG1File(Context context) {
        SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(context);
        if (sharedPref.getBoolean("DG1FileCached", false)) {
            Log.i(TAG, "Accessing cached DG.");
            try {
                FileInputStream fileInputStream = context.openFileInput("DG1File");
                BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
                return new DG1File(bufferedInputStream);
            } catch (IOException e) {
                Log.e(TAG, "Error reading cached file!");
            }
        }
        DG1File file = null;
        try {
            file = new DG1File(passportService.getInputStream(EF_DG1));
        } catch (CardServiceException | IOException e){
            Log.e(TAG, "Error reading passport file");
        }
        try {
            FileOutputStream fileOutputStream = context.openFileOutput("DG1File", Context.MODE_PRIVATE);
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
            bufferedOutputStream.write(file.getEncoded());
            bufferedOutputStream.close();
            fileOutputStream.close();
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.putBoolean("DG1FileCached", true);
            editor.apply();

        } catch (IOException e) {
            Log.e(TAG, "Error caching file!");
        }

        return file;
    }

    /**
     * Read DG14 File from an eID
     * @param context App context - used for caching
     */
    public DG14File readDG14File(Context context) {
        SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(context);
        if (sharedPref.getBoolean("DG14FileCached", false)) {
            Log.i(TAG, "Accessing cached DG.");
            try {
                FileInputStream fileInputStream = context.openFileInput("DG14File");
                BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
                return new DG14File(bufferedInputStream);
            } catch (IOException e) {
                Log.e(TAG, "Error reading cached file!");
            }
        }
        DG14File file = null;
        try {
            file = new DG14File(passportService.getInputStream(EF_DG14));
        } catch (CardServiceException | IOException e){
            Log.e(TAG, "Error reading passport file");
        }
        try {
            FileOutputStream fileOutputStream = context.openFileOutput("DG14File", Context.MODE_PRIVATE);
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
            bufferedOutputStream.write(file.getEncoded());
            bufferedOutputStream.close();
            fileOutputStream.close();
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.putBoolean("DG14FileCached", true);
            editor.apply();

        } catch (IOException e) {
            Log.e(TAG, "Error caching file!");
        }

        return file;
    }

    /**
     * Read SOD File from an eID
     * @param context App context - used for caching
     */
    public SODFile readSODFile(Context context) {
        SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(context);
        if (sharedPref.getBoolean("SODFileCached", false)) {
            Log.i(TAG, "Accessing cached DG.");
            String[] files = context.fileList();
            for (String fileName : files){
                Log.i(TAG, "Available file: " + fileName);
            }
            try {
                FileInputStream fileInputStream = context.openFileInput("SODFile");
                BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
                return new SODFile(bufferedInputStream);
            } catch (IOException e) {
                Log.e(TAG, "Error reading cached file!");
            }
        }
        SODFile file = null;
        try {
            file = new SODFile(passportService.getInputStream(EF_SOD));
        } catch (CardServiceException | IOException e){
            Log.e(TAG, "Error reading passport file");
        }
        try {
            FileOutputStream fileOutputStream = context.openFileOutput("SODFile", Context.MODE_PRIVATE);
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
            bufferedOutputStream.write(file.getEncoded());
            bufferedOutputStream.close();
            fileOutputStream.close();
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.putBoolean("SODFileCached", true);
            editor.apply();

        } catch (IOException e) {
            Log.e(TAG, "Error caching file!");
        }

        return file;
    }

}


