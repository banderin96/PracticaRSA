package com.example.practicarsa;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.util.Xml;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.xmlpull.v1.XmlSerializer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


class RSA {

    public PrivateKey PrivateKey = null;
    public PublicKey PublicKey = null;

    public Context context;

    public RSA()
    {


    }

    public Context getContext() {
        return context;
    }

    public void setContext(Context context) {
        this.context = context;
    }

    public void setPrivateKeyString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException{
        byte[] encodedPrivateKey = stringToBytes(key);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        java.security.PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        this.PrivateKey = privateKey;
    }

    public void setPublicKeyString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException{

        byte[] encodedPublicKey = stringToBytes(key);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        this.PublicKey = publicKey;
    }

    public String getPrivateKeyString(){
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(this.PrivateKey.getEncoded());
        return bytesToString(pkcs8EncodedKeySpec.getEncoded());
    }

    public String getPublicKeyString(){
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(this.PublicKey.getEncoded());
        return bytesToString(x509EncodedKeySpec.getEncoded());
    }


    public void genKeyPair(int size) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException  {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        KeyPair kp = kpg.genKeyPair();

        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        this.PrivateKey = privateKey;
        this.PublicKey = publicKey;
    }

    public String Encrypt(String plain) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException,IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, NoSuchProviderException {

        byte[] encryptedBytes;

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.PublicKey);
        encryptedBytes = cipher.doFinal(plain.getBytes());

        return bytesToString(encryptedBytes);

    }

    public String Decrypt(String result) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        byte[] decryptedBytes;

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, this.PrivateKey);
        decryptedBytes = cipher.doFinal(stringToBytes(result));
        return new String(decryptedBytes);
    }

    public String bytesToString(byte[] b) {
        byte[] b2 = new byte[b.length + 1];
        b2[0] = 1;
        System.arraycopy(b, 0, b2, 1, b.length);
        return new BigInteger(b2).toString(36);
    }

    public byte[] stringToBytes(String s) {
        byte[] b2 = new BigInteger(s, 36).toByteArray();
        return Arrays.copyOfRange(b2, 1, b2.length);
    }


    public void saveToDiskPrivateKey(String path){
        try {
            FileOutputStream outputStream = null;
            outputStream =  this.context.openFileOutput(path, Context.MODE_PRIVATE);
            outputStream.write(this.getPrivateKeyString().getBytes());
            outputStream.close();
        } catch (Exception e) {
            Log.d("RSA:","Error write PrivateKey");
        }
    }

    public void saveToDiskPublicKey(String path) {
        try {
            FileOutputStream outputStream = null;
            outputStream =  this.context.openFileOutput(path, Context.MODE_PRIVATE);
            outputStream.write(this.getPublicKeyString().getBytes());
            outputStream.close();
        } catch (Exception e) {
            Log.d("RSA:","Error write Public");
        }
    }

    public void openFromDiskPublicKey(String path) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        String content = this.readFileAsString(path);
        this.setPublicKeyString(content);
    }

    public void openFromDiskPrivateKey(String path) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        String content = this.readFileAsString(path);
        this.setPrivateKeyString(content);
    }


    private String readFileAsString(String filePath) throws IOException {

        BufferedReader fin = new BufferedReader(new InputStreamReader(context.openFileInput(filePath)));
        String txt = fin.readLine();
        fin.close();
        return txt;

    }

}


public class MainActivity extends AppCompatActivity {


    String xml_data;
    EditText inputText;
    Button boton_encriptar;
    TextView encoded;
    TextView decoded;
    XmlSerializer ser = Xml.newSerializer();
    Date now = Calendar.getInstance().getTime();
    Integer next_id;
    Context context;



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inputText = findViewById(R.id.plain_text_input);
        boton_encriptar = findViewById(R.id.button);
        encoded = findViewById(R.id.encoded);
        decoded = findViewById(R.id.decoded);

        boton_encriptar.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                try {

                    //Obtenemos el texto desde el cuadro de texto
                    String original = inputText.getText().toString();

                    RSA rsa = new RSA();

                    //le asignamos el Contexto
                    rsa.setContext(getBaseContext());

                    //Generamos un juego de claves
                    rsa.genKeyPair(1024);

                    //Guardamos en la memoria las claves
                    rsa.saveToDiskPrivateKey("rsa.pri");
                    rsa.saveToDiskPublicKey("rsa.pub");

                    //Ciframos
                    String encode_text = rsa.Encrypt(original);

                    //Mostramos el texto ya descifrado
                    encoded.setText(encode_text);

                    //Creamos otro objeto de nuestra clase RSA
                    RSA rsa2 = new RSA();

                    //Le pasamos el contexto
                    rsa2.setContext(getBaseContext());

                    //Cargamos las claves que creamos anteriormente
                    rsa2.openFromDiskPrivateKey("rsa.pri");
                    rsa2.openFromDiskPublicKey("rsa.pub");

                    //Desciframos
                    String decode_text = rsa2.Decrypt(encode_text);

                    //Mostramos el texto ya descifrado
                    decoded.setText(decode_text);
                } catch (Exception e) {

                }

                //Buscamos que exista el archivo xml
                File archivo_xml = new File(getApplicationContext().getFilesDir(), "encrypted_data.xml");
                if (archivo_xml.exists()) {

                    //SI EXISTE COMPROBAMOS EL ID MÁS ALTO PARA ASIGNARLE EL CORRECTO A LA NUEVA ENTRADA <DATA>

                    try {
                        FileInputStream fis = openFileInput("encrypted_data.xml");
                        BufferedReader filexml = new BufferedReader(new InputStreamReader(fis));


                        //GUARDAMOS EL ID DE LA NUEVA <DATA> EN LA VARIABLE "next_id"
                        while (true) {
                            try {

                                xml_data = filexml.readLine();
                                if (xml_data.contains("<data")) {


                                    next_id = Integer.parseInt(xml_data.substring(11, 12))+1;
                                    Log.e("next_id", "El id de la nueva entrada es ==> " + next_id.toString());

                                }
                                if (xml_data.contains("/content")) {

                                    Log.e("test_id", "endwhile" + xml_data);

                                    break;
                                }
                            } catch (Exception e){
                            }

                        }
                        filexml.close();
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    //Añadimos la nueva entrada de texto plano y cifrado como una nueva <data>

                    try {
                        String all_data = new String();
                        Scanner reader = new Scanner(new FileInputStream(archivo_xml), "UTF-8");
                        while(reader.hasNextLine()) {
                            all_data = all_data + reader.nextLine() + "\n";
                        }
                        reader.close();

                        //Eliminamos el cierre de la etiqueta raíz
                        all_data = all_data.substring(0,all_data.indexOf("</co"));

                        //Añadimos la nueva entrada
                        all_data = all_data + "\t<data id=\""+ next_id.toString() +"\">\n\t\t<time>" + now.toString() + "</time>\n\t\t<text>" + decoded.getText().toString() + "</text>\n\t\t<cipher_text>" + encoded.getText().toString() + "</cipher_text>\n\t</data>\n</content_file>";

                        //Sobreescribimos el fichero "encrypted_data.xml" con el nuevo string all_data
                        BufferedWriter writer = new BufferedWriter(new FileWriter(archivo_xml, false));
                        writer.write(all_data);
                        writer.flush();
                        writer.close();

                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                } else if (!archivo_xml.exists()){

                    //CREAMOS FICHERO XML
                    try {

                        OutputStreamWriter fout =
                                new OutputStreamWriter(
                                        openFileOutput("encrypted_data.xml",
                                                Context.MODE_PRIVATE));
                        ser.setOutput(fout);
                        ser.startTag("", "content_file");
                        ser.text("\n\t");
                        ser.startTag("", "data").attribute("", "id", "1");
                        ser.text("\n\t\t");
                        ser.startTag("", "time");
                        ser.text(now.toString());
                        ser.endTag("", "time");
                        ser.text("\n\t\t");
                        ser.startTag("", "text");
                        ser.text(decoded.getText().toString());
                        ser.endTag("", "text");
                        ser.text("\n\t\t");
                        ser.startTag("", "cipher_text");
                        ser.text(encoded.getText().toString());
                        ser.endTag("", "cipher_text");
                        ser.text("\n\t");
                        ser.endTag("", "data");
                        ser.text("\n");
                        ser.endTag("", "content_file");
                        ser.endDocument();

                        fout.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }



            }

        });



    }
}
