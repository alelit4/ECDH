package com.cryptull.alexandra.ecdh;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;

import org.spongycastle.jcajce.provider.config.ConfigurableProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECCurve;

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

import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

import javax.crypto.KeyAgreement;

public class MainActivity extends AppCompatActivity {

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    BigInteger q = new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16);
    BigInteger a = new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16);
    BigInteger b = new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16);
    BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307", 16);
    byte[] G_hex = Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf");
    org.spongycastle.math.ec.ECPoint G;

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

                    ECCurve curve = new ECCurve.Fp( q, a, b);
                    G = curve.decodePoint(G_hex);
                    ECParameterSpec ecSpec = new ECParameterSpec( curve, G, n);
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
