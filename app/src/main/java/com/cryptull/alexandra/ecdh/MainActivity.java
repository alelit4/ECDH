package com.cryptull.alexandra.ecdh;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;

import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;

public class MainActivity extends AppCompatActivity {

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                KeyPairGenerator keyGen = null;
                try {
                    keyGen = KeyPairGenerator.getInstance("ECDH", "SC");
                    EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger(
                            "fffffffffffffffffffffffffffffffeffffffffffffffff", 16)), new BigInteger(
                            "fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger(
                            "fffffffffffffffffffffffffffffffefffffffffffffffc", 16));


                    ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
                    keyGen.initialize(ecSpec, new SecureRandom());



                    KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "SC");
                    KeyPair aPair = keyGen.generateKeyPair();
                    KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "SC");
                    KeyPair bPair = keyGen.generateKeyPair();

                    aKeyAgree.init(aPair.getPrivate());
                    bKeyAgree.init(bPair.getPrivate());

                    aKeyAgree.doPhase(bPair.getPublic(), true);
                    bKeyAgree.doPhase(aPair.getPublic(), true);

                    MessageDigest hash = MessageDigest.getInstance("SHA1", "SC");

                    System.out.println(new String(hash.digest(aKeyAgree.generateSecret())));
                    System.out.println(new String(hash.digest(bKeyAgree.generateSecret())));
                    Snackbar.make(view, new String(hash.digest(aKeyAgree.generateSecret())) + new String(hash.digest(bKeyAgree.generateSecret())), Snackbar.LENGTH_LONG)
                            .setAction("Action", null).show();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                }

            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
