package edu.uw.medhas.mhealthsecurityframework;

import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.support.design.widget.NavigationView;
import android.support.v4.view.GravityCompat;
import android.support.v4.widget.DrawerLayout;
import android.support.v7.app.ActionBarDrawerToggle;
import android.support.v7.widget.Toolbar;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import edu.uw.medhas.mhealthsecurityframework.activity.SecureActivity;
import edu.uw.medhas.mhealthsecurityframework.model.SecureAnnotatedModel;
import edu.uw.medhas.mhealthsecurityframework.model.SecureSerializableModel;
import edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity.SecureDatabase;
import edu.uw.medhas.mhealthsecurityframework.model.secureDatabaseModel.entity.SensitiveDbData;
import edu.uw.medhas.mhealthsecurityframework.password.PasswordUtils;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoLowerCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoNumberCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoSpecialCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordNoUpperCaseCharacterException;
import edu.uw.medhas.mhealthsecurityframework.password.exception.PasswordTooShortException;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureDouble;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureFloat;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureInteger;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureLong;
import edu.uw.medhas.mhealthsecurityframework.storage.database.model.SecureString;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResult;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultSuccess;
import edu.uw.medhas.mhealthsecurityframework.web.model.Request;
import edu.uw.medhas.mhealthsecurityframework.web.model.RequestMethod;
import edu.uw.medhas.mhealthsecurityframework.web.model.Response;
import edu.uw.medhas.mhealthsecurityframework.web.model.Error;
import edu.uw.medhas.mhealthsecurityframework.web.model.ResponseHandler;
import edu.uw.medhas.mhealthsecurityframework.webclient.TestWebClient;

public class MainActivity extends SecureActivity
        implements NavigationView.OnNavigationItemSelectedListener {

    private SecureDatabase mSecureDatabase;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.addDrawerListener(toggle);
        toggle.syncState();

        NavigationView navigationView = (NavigationView) findViewById(R.id.nav_view);
        navigationView.setNavigationItemSelectedListener(this);

        mSecureDatabase = App.get().getDb();

        // Delete keys
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            keyStore.deleteEntry("mhealth-security-framework-internal-storage");
            keyStore.deleteEntry("mhealth-security-framework-external-storage");
            keyStore.deleteEntry("mhealth-security-framework-database-storage");
            keyStore.deleteEntry("mhealth-security-framework-cache-storage");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void onBackPressed() {
        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onNavigationItemSelected(MenuItem item) {
        // Handle navigation view item clicks here.
        int id = item.getItemId();

        View newView = null;
        final LayoutInflater inflater = (LayoutInflater)getSystemService(Context.LAYOUT_INFLATER_SERVICE);

        if (id == R.id.nav_password) {
            newView = inflater.inflate(R.layout.content_pwstrchecker, null);
        } else if (id == R.id.nav_cache_serializable) {
            newView = inflater.inflate(R.layout.content_cacsto_slz, null);
        } else if (id == R.id.nav_cache_annotation) {
            newView = inflater.inflate(R.layout.content_cacsto_ano, null);
        } else if (id == R.id.nav_internal_serializable) {
            newView = inflater.inflate(R.layout.content_intsto_slz, null);
        } else if (id == R.id.nav_internal_annotation) {
            newView = inflater.inflate(R.layout.content_intsto_ano, null);
        } else if (id == R.id.nav_external_serializable) {
            newView = inflater.inflate(R.layout.content_extsto_slz, null);
        } else if (id == R.id.nav_external_annotation) {
            newView = inflater.inflate(R.layout.content_extsto_ano, null);
        } else if (id == R.id.nav_db_tc) {
            newView = inflater.inflate(R.layout.content_dbsto_tc, null);
        } else if (id == R.id.nav_ssl) {
            newView = inflater.inflate(R.layout.content_ssl_checker, null);
        }

        LinearLayout mainLayout = (LinearLayout) findViewById(R.id.main_container);
        mainLayout.removeAllViews();
        mainLayout.addView(newView);

        if (id == R.id.nav_password) {
            final EditText editTextPw = (EditText) findViewById(R.id.password);
            final Button btnCreateAccount = (Button) findViewById(R.id.createAccount);

            btnCreateAccount.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    final String passwordStr = editTextPw.getText().toString();

                    try {
                        PasswordUtils.validatePassword(passwordStr);
                        Toast.makeText(getApplicationContext(),
                                "Password is strong", Toast.LENGTH_LONG).show();
                    } catch (PasswordTooShortException ptsex) {
                        Toast.makeText(getApplicationContext(),
                                "Password is too small", Toast.LENGTH_LONG).show();
                    } catch (PasswordNoUpperCaseCharacterException pnuccex) {
                        Toast.makeText(getApplicationContext(),
                                "Password has no upper case character",
                                Toast.LENGTH_LONG).show();
                    } catch (PasswordNoLowerCaseCharacterException pnlccex) {
                        Toast.makeText(getApplicationContext(),
                                "Password has no lower case character",
                                Toast.LENGTH_LONG).show();
                    } catch (PasswordNoNumberCharacterException pnncex) {
                        Toast.makeText(getApplicationContext(),
                                "Password has no number", Toast.LENGTH_LONG).show();
                    } catch (PasswordNoSpecialCharacterException pnscex) {
                        Toast.makeText(getApplicationContext(), "Password has no special character",
                                Toast.LENGTH_LONG).show();
                    }
                }
            });
        } else if (id == R.id.nav_cache_serializable) {
            final EditText editTextInp = (EditText) findViewById(R.id.cacSlzSensitiveInp);
            final Button btnStore = (Button) findViewById(R.id.cacSlzStore);
            final TextView editTextOp = (TextView) findViewById(R.id.cacSlzSensitiveOp);
            final Button btnRetrieve = (Button) findViewById(R.id.cacSlzRetrieve);

            btnStore.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final StorageWriteObject<SecureSerializableModel> writeObject =
                            new StorageWriteObject<>("cachestorage-serializable.txt",
                                    new SecureSerializableModel(editTextInp.getText().toString()));
                    getSecureCacheHandler().writeData(writeObject,
                        new StorageResultCallback<StorageResultSuccess>() {
                            @Override
                            public void onWaitingForAuthentication() {
                                editTextOp.setText("Waiting for Authentication");
                            }

                            @Override
                            public void onSuccess(StorageResult<StorageResultSuccess> storageResult) {
                                editTextOp.setText("Successfully stored file");
                            }

                            @Override
                            public void onFailure(StorageResultErrorType errorType) {
                                editTextOp.setText("Error storing file: " + errorType.name());
                            }
                        }
                    );
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final StorageReadObject<SecureSerializableModel> readObject =
                            new StorageReadObject<>("cachestorage-serializable.txt",
                                    SecureSerializableModel.class);
                    getSecureCacheHandler().readData(readObject,
                        new StorageResultCallback<SecureSerializableModel>() {
                            @Override
                            public void onWaitingForAuthentication() {
                                editTextOp.setText("Waiting for Authentication");
                            }

                            @Override
                            public void onSuccess(StorageResult<SecureSerializableModel> storageResult) {
                                editTextOp.setText(storageResult.getResult().getData());
                            }

                            @Override
                            public void onFailure(StorageResultErrorType errorType) {
                                editTextOp.setText("Error retrieving file: " + errorType.name());
                            }
                        }
                    );
                }
            });

        } else if (id == R.id.nav_cache_annotation) {

            final EditText editTextInp = (EditText) findViewById(R.id.cacAnoSensitiveInp);
            final Button btnStore = (Button) findViewById(R.id.cacAnoStore);
            final TextView editTextOp = (TextView) findViewById(R.id.cacAnoSensitiveOp);
            final Button btnRetrieve = (Button) findViewById(R.id.cacAnoRetrieve);

            btnStore.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final SecureAnnotatedModel sam = new SecureAnnotatedModel();
                    sam.setData(editTextInp.getText().toString());

                    final StorageWriteObject<SecureAnnotatedModel> writeObject =
                            new StorageWriteObject<>("cachestorage-annotation.txt", sam);

                    getSecureCacheHandler().writeData(writeObject,
                            new StorageResultCallback<StorageResultSuccess>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<StorageResultSuccess> storageResult) {
                                    editTextOp.setText("Successfully stored file");
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error storing file: " + errorType.name());
                                }
                            }
                    );
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final StorageReadObject<SecureAnnotatedModel> readObject =
                            new StorageReadObject<>("cachestorage-annotation.txt",
                                    SecureAnnotatedModel.class);
                    getSecureCacheHandler().readData(readObject,
                            new StorageResultCallback<SecureAnnotatedModel>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<SecureAnnotatedModel> storageResult) {
                                    editTextOp.setText(storageResult.getResult().getData());
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error retrieving file: " + errorType.name());
                                }
                            }
                    );
                }
            });

        } else if (id == R.id.nav_internal_serializable) {
            final EditText editTextInp = (EditText) findViewById(R.id.intSlzSensitiveInp);
            final Button btnStore = (Button) findViewById(R.id.intSlzStore);
            final TextView editTextOp = (TextView) findViewById(R.id.intSlzSensitiveOp);
            final Button btnRetrieve = (Button) findViewById(R.id.intSlzRetrieve);

            btnStore.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final StorageWriteObject<SecureSerializableModel> writeObject =
                            new StorageWriteObject<>("internalstorage-serializable.txt",
                                    new SecureSerializableModel(editTextInp.getText().toString()));
                    getSecureInternalFileHandler().writeData(writeObject,
                            new StorageResultCallback<StorageResultSuccess>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<StorageResultSuccess> storageResult) {
                                    editTextOp.setText("Successfully stored file");
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error storing file: " + errorType.name());
                                }
                            });
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final StorageReadObject<SecureSerializableModel> readObject =
                            new StorageReadObject<>("internalstorage-serializable.txt",
                                    SecureSerializableModel.class);
                    getSecureInternalFileHandler().readData(readObject,
                            new StorageResultCallback<SecureSerializableModel>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(
                                        StorageResult<SecureSerializableModel> storageResult) {
                                    editTextOp.setText(storageResult.getResult().getData());
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error retrieving file: " + errorType.name());
                                }
                            });
                }
            });

        } else if (id == R.id.nav_internal_annotation) {

            final EditText editTextInp = (EditText) findViewById(R.id.intAnoSensitiveInp);
            final Button btnStore = (Button) findViewById(R.id.intAnoStore);
            final TextView editTextOp = (TextView) findViewById(R.id.intAnoSensitiveOp);
            final Button btnRetrieve = (Button) findViewById(R.id.intAnoRetrieve);

            btnStore.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final SecureAnnotatedModel sam = new SecureAnnotatedModel();
                    sam.setData(editTextInp.getText().toString());

                    final StorageWriteObject<SecureAnnotatedModel> writeObject =
                            new StorageWriteObject<>("internalstorage-annotation.txt", sam);

                    getSecureInternalFileHandler().writeData(writeObject,
                            new StorageResultCallback<StorageResultSuccess>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<StorageResultSuccess> storageResult) {
                                    editTextOp.setText("Successfully stored file");
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error storing file: " + errorType.name());
                                }
                            });
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final StorageReadObject<SecureAnnotatedModel> readObject =
                            new StorageReadObject<>("internalstorage-annotation.txt",
                                    SecureAnnotatedModel.class);

                    getSecureInternalFileHandler().readData(readObject,
                            new StorageResultCallback<SecureAnnotatedModel>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<SecureAnnotatedModel> storageResult) {
                                    editTextOp.setText(storageResult.getResult().getData());
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error retrieving file: " + errorType.name());
                                }
                            });
                }
            });

        } else if (id == R.id.nav_external_serializable) {
            final EditText editTextInp = (EditText) findViewById(R.id.extSlzSensitiveInp);
            final Button btnStore = (Button) findViewById(R.id.extSlzStore);
            final TextView editTextOp = (TextView) findViewById(R.id.extSlzSensitiveOp);
            final Button btnRetrieve = (Button) findViewById(R.id.extSlzRetrieve);

            btnStore.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final StorageWriteObject<SecureSerializableModel> writeObject =
                            new StorageWriteObject<>("externalstorage-serializable.txt",
                                    new SecureSerializableModel(editTextInp.getText().toString()));
                    final SecureSerializableModel ssm =
                            new SecureSerializableModel(editTextInp.getText().toString());
                    getSecureExternalFileHandler().writeData(Environment.DIRECTORY_DOCUMENTS,
                            writeObject,
                            new StorageResultCallback<StorageResultSuccess>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(
                                        StorageResult<StorageResultSuccess> storageResult) {
                                    editTextOp.setText("Successfully stored file");
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error storing file: " + errorType.name());
                                }
                            });
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    final StorageReadObject<SecureSerializableModel> readObject =
                            new StorageReadObject<>("externalstorage-serializable.txt",
                                    SecureSerializableModel.class);
                    getSecureExternalFileHandler().readData(Environment.DIRECTORY_DOCUMENTS,
                            readObject,
                            new StorageResultCallback<SecureSerializableModel>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(
                                        StorageResult<SecureSerializableModel> storageResult) {
                                    editTextOp.setText(storageResult.getResult().getData());
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error retrieving file: " + errorType.name());
                                }
                            });
                }
            });

        } else if (id == R.id.nav_external_annotation) {
            final EditText editTextInp = (EditText) findViewById(R.id.extAnoSensitiveInp);
            final Button btnStore = (Button) findViewById(R.id.extAnoStore);
            final TextView editTextOp = (TextView) findViewById(R.id.extAnoSensitiveOp);
            final Button btnRetrieve = (Button) findViewById(R.id.extAnoRetrieve);

            btnStore.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final SecureAnnotatedModel sam = new SecureAnnotatedModel();
                    sam.setData(editTextInp.getText().toString());

                    final StorageWriteObject<SecureAnnotatedModel> writeObject =
                            new StorageWriteObject<>("externalstorage-annotation.txt", sam);

                    getSecureExternalFileHandler().writeData(Environment.DIRECTORY_DOCUMENTS,
                            writeObject,
                            new StorageResultCallback<StorageResultSuccess>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<StorageResultSuccess> storageResult) {
                                    editTextOp.setText("Successfully stored file");
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error storing file: " + errorType.name());
                                }
                            });
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final StorageReadObject<SecureAnnotatedModel> readObject =
                            new StorageReadObject<>("externalstorage-annotation.txt",
                                    SecureAnnotatedModel.class);
                    getSecureExternalFileHandler().readData(Environment.DIRECTORY_DOCUMENTS,
                            readObject,
                            new StorageResultCallback<SecureAnnotatedModel>() {
                                @Override
                                public void onWaitingForAuthentication() {
                                    editTextOp.setText("Waiting for Authentication");
                                }

                                @Override
                                public void onSuccess(StorageResult<SecureAnnotatedModel> storageResult) {
                                    editTextOp.setText(storageResult.getResult().getData());
                                }

                                @Override
                                public void onFailure(StorageResultErrorType errorType) {
                                    editTextOp.setText("Error retrieving file: " + errorType.name());
                                }
                            });
                }
            });
        } else if (id == R.id.nav_db_tc) {
            final EditText editTextIntInp = (EditText) findViewById(R.id.dbTcSensitiveIntInp);
            final EditText editTextLongInp = (EditText) findViewById(R.id.dbTcSensitiveLongInp);
            final EditText editTextFloatInp = (EditText) findViewById(R.id.dbTcSensitiveFloatInp);
            final EditText editTextDoubleInp = (EditText) findViewById(R.id.dbTcSensitiveDoubleInp);
            final EditText editTextStringInp = (EditText) findViewById(R.id.dbTcSensitiveStringInp);

            final Button btnStore = (Button) findViewById(R.id.dbTcStore);
            final TextView editTextOp = (TextView) findViewById(R.id.dbTcSensitiveOp);
            final Button btnRetrieve = (Button) findViewById(R.id.dbTcRetrieve);

            btnStore.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    //Database Insert
                    try {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                SensitiveDbData object = new SensitiveDbData();
                                object.setIntValue(new SecureInteger(
                                        Integer.valueOf(editTextIntInp.getText().toString())));
                                object.setLongValue(new SecureLong(
                                        Long.valueOf(editTextLongInp.getText().toString())));
                                object.setFloatValue(new SecureFloat(
                                        Float.valueOf(editTextFloatInp.getText().toString())));
                                object.setDoubleValue(new SecureDouble(
                                        Double.valueOf(editTextDoubleInp.getText().toString())));
                                object.setStringValue(new SecureString(
                                        editTextStringInp.getText().toString()));
                                object.setSimpleStr(editTextStringInp.getText().toString());

                                Long id = mSecureDatabase.daoAccess().insertSingle(object);

                                editTextOp.setText(id.toString());
                            }
                        });
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    //Database Fetch
                    try {
                        runOnUiThread(new Runnable() {

                            @Override
                            public void run() {
                                String id = (String) editTextOp.getText();
                                SensitiveDbData object = mSecureDatabase.daoAccess()
                                        .fetchOnebyId(Integer.valueOf(id));
                                editTextOp.setText(
                                          "Integer: " + String.valueOf(object.getIntValue().getValue())
                                        + ", Long: " +String.valueOf(object.getLongValue().getValue())
                                        + ", Float: " + String.valueOf(object.getFloatValue().getValue())
                                        + ", Double: " + String.valueOf(object.getDoubleValue().getValue())
                                        + ", String: " + object.getStringValue().getValue()
                                        + ", SimString: " + object.getSimpleStr());

                            }
                        });
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });

        } else if (id == R.id.nav_ssl) {
            final EditText editTextUrl = (EditText) findViewById(R.id.sslCheckerUrl);
            final Button btnValidate = (Button) findViewById(R.id.sslCheckerBtn);
            final TextView editTextOp = (TextView) findViewById(R.id.sslCheckerOp);

            btnValidate.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    final String url = editTextUrl.getText().toString();

                    final TestWebClient webClient = new TestWebClient(
                            new ResponseHandler() {

                                @Override
                                public void onSuccess(Response response) {
                                    editTextOp.setText("Connected successfully to: " + url);
                                }

                                @Override
                                public void onError(Error error) {
                                    editTextOp.setText("Can't allow to connect to " + url + " because of: "
                                            + error.toString());
                                }
                            });

                    webClient.execute(new Request(url, RequestMethod.GET));
                }
            });
        }

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
    }
}
