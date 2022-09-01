package de.cispa.feido;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import logoverwrite.Log;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;

import org.jmrtd.BACKeySpec;
import org.jmrtd.PACEKeySpec;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

public class MainActivity extends AppCompatActivity {

    private final String TAG = this.getClass().getSimpleName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // redirect NFC intent

        // get variables for text fields
        EditText docNumField = findViewById(R.id.editTextDocNum);
        EditText birthDateField = findViewById(R.id.editTextDateBirth);
        EditText expDateField = findViewById(R.id.editTextDateExp);

        // read variables from storage
        SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext() );
        String documentNumber = sharedPref.getString("documentNumber", "");
        String birthDate = sharedPref.getString("birthDate", "");
        String expiryDate = sharedPref.getString("expiryDate", "");

        if (sharedPref.getBoolean("cardAccessFileCached", false)){
            ((CheckBox) findViewById(R.id.checkBox3)).setChecked(true);
        }

        // set text field from variables read from storage
        docNumField.setText(documentNumber);
        birthDateField.setText(birthDate);
        expDateField.setText(expiryDate);


        //Button to save MRZ to shared preferences
        final Button button2 = findViewById(R.id.button2);
        button2.setOnClickListener(v -> {
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.putString("documentNumber", docNumField.getText().toString());
            editor.putString("birthDate", birthDateField.getText().toString());
            editor.putString("expiryDate", expDateField.getText().toString());
            editor.apply();
        });

        //Button to toggle password visibility
        final Button button3 = findViewById(R.id.button3);
        button3.setOnClickListener(v -> {
            if (docNumField.getTransformationMethod() == PasswordTransformationMethod.getInstance()){
               docNumField.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
               birthDateField.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
               expDateField.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
            }
            else {
                docNumField.setTransformationMethod(PasswordTransformationMethod.getInstance());
                birthDateField.setTransformationMethod(PasswordTransformationMethod.getInstance());
                expDateField.setTransformationMethod(PasswordTransformationMethod.getInstance());
            }
        });

        //Button to delete cached DGs
        final Button buttonClear = findViewById(R.id.button);
        buttonClear.setOnClickListener(v -> {
            SharedPreferences.Editor editor = sharedPref.edit();
            if (sharedPref.getBoolean("cardAccessFileCached", false)) {
                getApplicationContext().deleteFile("cardAccessFile");
                editor.putBoolean("cardAccessFileCached", false);
            }
            if (sharedPref.getBoolean("DG1FileCached", false)) {
                getApplicationContext().deleteFile("DG1File");
                editor.putBoolean("DG1FileCached", false);
            }
            if (sharedPref.getBoolean("DG14FileCached", false)) {
                getApplicationContext().deleteFile("DG14File");
                editor.putBoolean("DG14FileCached", false);
            }
            if (sharedPref.getBoolean("SODFileCached", false)) {
                getApplicationContext().deleteFile("SODFile");
                editor.putBoolean("SODFileCached", false);
            }

            ((CheckBox) findViewById(R.id.checkBox3)).setChecked(false);
            editor.apply();

        });

    }


    public synchronized PACEKeySpec getPaceKey(){
        SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
        String documentNumber = sharedPref.getString("documentNumber", "");
        String birthDate = sharedPref.getString("birthDate", "");
        String expiryDate = sharedPref.getString("expiryDate", "");
        BACKeySpec bacKeySpec = new BACKeySpec() {
            @Override
            public String getDocumentNumber() {
                return documentNumber;
            }
            @Override
            public String getDateOfBirth() {
                return birthDate;
            }
            @Override
            public String getDateOfExpiry() {
                return expiryDate;
            }
            @Override
            public String getAlgorithm() {
                return null;
            }
            @Override
            public byte[] getKey() {
                return new byte[0];
            }
        };
        PACEKeySpec paceKeySpec = null;
        try {
            Log.i(TAG, bacKeySpec.toString());
            paceKeySpec = PACEKeySpec.createMRZKey(bacKeySpec);
        } catch (GeneralSecurityException e) {
            Log.e(TAG, "Error initializing MRZKey");
            Log.e(TAG, e.getMessage());
        }
        return paceKeySpec;
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if(NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            InputStream iasRootStream = null;
            try {
                iasRootStream = getAssets().open("Intel_SGX_Attestation_RootCA.pem");
                iasRootStream.mark(10000);
            }
            catch (IOException e){
                Log.e(TAG, "Couldn't open Intel_SGX_Attestation_RootCA.pem from /assets!");
            }

            StateBasket stateBasket = new StateBasket(tag, getPaceKey(), iasRootStream, this);
            new LinearFEIDO().execute(stateBasket);
        }
    }

}
