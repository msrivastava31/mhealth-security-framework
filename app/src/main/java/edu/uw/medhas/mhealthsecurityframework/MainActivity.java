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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import edu.uw.medhas.mhealthsecurityframework.acl.db.DbError;
import edu.uw.medhas.mhealthsecurityframework.acl.db.ResultHandler;
import edu.uw.medhas.mhealthsecurityframework.acl.model.AuthContext;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Privilege;
import edu.uw.medhas.mhealthsecurityframework.acl.model.Role;
import edu.uw.medhas.mhealthsecurityframework.acl.model.User;
import edu.uw.medhas.mhealthsecurityframework.acl.model.UserRole;
import edu.uw.medhas.mhealthsecurityframework.acl.service.PrivilegeService;
import edu.uw.medhas.mhealthsecurityframework.acl.service.RoleService;
import edu.uw.medhas.mhealthsecurityframework.acl.service.UserService;
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
import edu.uw.medhas.mhealthsecurityframework.storage.exception.ReauthenticationException;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageReadObject;
import edu.uw.medhas.mhealthsecurityframework.storage.metadata.StorageWriteObject;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResult;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultCallback;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultErrorType;
import edu.uw.medhas.mhealthsecurityframework.storage.result.StorageResultSuccess;
import edu.uw.medhas.mhealthsecurityframework.web.model.Request;
import edu.uw.medhas.mhealthsecurityframework.web.model.RequestMethod;
import edu.uw.medhas.mhealthsecurityframework.web.model.Response;
import edu.uw.medhas.mhealthsecurityframework.web.model.WebError;
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

        if (id == R.id.nav_password_ui) {
            newView = inflater.inflate(R.layout.content_pwdvalidator_ui, null);
        } else if (id == R.id.nav_password_be) {
            newView = inflater.inflate(R.layout.content_pwdvalidator_be, null);
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
        } else if (id == R.id.nav_acl_user) {
            newView = inflater.inflate(R.layout.content_acl_user, null);
        } else if (id == R.id.nav_acl_role) {
            newView = inflater.inflate(R.layout.content_acl_role, null);
        } else if (id == R.id.nav_acl_privilege) {
            newView = inflater.inflate(R.layout.content_acl_privilege, null);
        }

        LinearLayout mainLayout = (LinearLayout) findViewById(R.id.main_container);
        mainLayout.removeAllViews();
        mainLayout.addView(newView);

        if (id == R.id.nav_password_be) {
            final EditText editTextPw = (EditText) findViewById(R.id.passwordBe);
            final TextView editTextOp = (TextView) findViewById(R.id.validatePasswordBeOp);
            final Button btnValidatePassword = (Button) findViewById(R.id.validatePasswordBe);

            btnValidatePassword.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    editTextOp.setText("");
                    final String passwordStr = editTextPw.getText().toString();

                    try {
                        PasswordUtils.validatePassword(passwordStr);
                        editTextOp.setText("Password is strong");
                    } catch (PasswordTooShortException ptsex) {
                        editTextOp.setText("Password is too small");
                    } catch (PasswordNoUpperCaseCharacterException pnuccex) {
                        editTextOp.setText("Password has no upper case character");
                    } catch (PasswordNoLowerCaseCharacterException pnlccex) {
                        editTextOp.setText("Password has no lower case character");
                    } catch (PasswordNoNumberCharacterException pnncex) {
                        editTextOp.setText("Password has no number");
                    } catch (PasswordNoSpecialCharacterException pnscex) {
                        editTextOp.setText("Password has no special character");
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
                    editTextOp.setText("");
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
                                editTextOp.setText("WebError storing file: " + errorType.name());
                            }
                        }
                    );
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
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
                                editTextOp.setText("WebError retrieving file: " + errorType.name());
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
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError storing file: " + errorType.name());
                                }
                            }
                    );
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError retrieving file: " + errorType.name());
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
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError storing file: " + errorType.name());
                                }
                            });
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError retrieving file: " + errorType.name());
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
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError storing file: " + errorType.name());
                                }
                            });
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError retrieving file: " + errorType.name());
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
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError storing file: " + errorType.name());
                                }
                            });
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError retrieving file: " + errorType.name());
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
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError storing file: " + errorType.name());
                                }
                            });
                }
            });

            btnRetrieve.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
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
                                    editTextOp.setText("WebError retrieving file: " + errorType.name());
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
                    } catch (ReauthenticationException raex) {
                        raex.printStackTrace();
                        startAuthenticationProcess();
                    } catch (Exception e) {
                        e.printStackTrace();
                        editTextOp.setText(e.getClass().getName());
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
                                        + ", String: " + object.getStringValue().getValue());

                            }
                        });
                    } catch (ReauthenticationException raex) {
                        raex.printStackTrace();
                        startAuthenticationProcess();
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
                    editTextOp.setText("");
                    final String url = editTextUrl.getText().toString();

                    final TestWebClient webClient = new TestWebClient(
                            new ResponseHandler() {

                                @Override
                                public void onSuccess(Response response) {
                                    editTextOp.setText("Connected successfully to: " + url);
                                }

                                @Override
                                public void onError(WebError error) {
                                    editTextOp.setText("Can't allow to connect to " + url + " because of: "
                                            + error.toString());
                                }
                            });

                    webClient.execute(new Request(url, RequestMethod.GET));
                }
            });
        } else if (id == R.id.nav_acl_user) {
            final EditText editTextNewUser = (EditText) findViewById(R.id.aclUserNewUser);
            final EditText editTextCurrentUser = (EditText) findViewById(R.id.aclUserCurrentUser);
            final Button btnCreate = (Button) findViewById(R.id.aclUserCreate);
            final Button btnDelete = (Button) findViewById(R.id.aclUserDelete);
            final TextView editTextOp = (TextView) findViewById(R.id.aclUserOp);

            final UserService userService = getAclServiceFactory().getUserService();

            btnCreate.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final User user = new User();
                    user.setId(editTextNewUser.getText().toString());
                    user.setName(user.getId() + "-name");

                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    userService.createUser(user, context, new ResultHandler<User>() {
                        @Override
                        public void onSuccess(User result) {
                            editTextOp.setText("Successfully created User: " + result.getId());
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });

            btnDelete.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final String userId = editTextNewUser.getText().toString();
                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    userService.deleteUser(userId, context, new ResultHandler<Void>() {
                        @Override
                        public void onSuccess(Void result) {
                            editTextOp.setText("Successfully deleted User");
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });

        } else if (id == R.id.nav_acl_role) {
            final EditText editTextNewRole = (EditText) findViewById(R.id.aclRoleNewRole);
            final EditText editTextCurrentUser = (EditText) findViewById(R.id.aclRoleCurrentUser);
            final Button btnCreate = (Button) findViewById(R.id.aclRoleCreate);
            final Button btnDelete = (Button) findViewById(R.id.aclRoleDelete);
            final TextView editTextOp = (TextView) findViewById(R.id.aclRoleOp);

            final RoleService roleService = getAclServiceFactory().getRoleService();

            btnCreate.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final Role role = new Role();
                    role.setName(editTextNewRole.getText().toString());

                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    roleService.createRole(role, context, new ResultHandler<Role>() {
                        @Override
                        public void onSuccess(Role result) {
                            editTextOp.setText("Successfully created Role: " + result.getId());
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });

            btnDelete.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final String roleId = editTextNewRole.getText().toString();
                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    roleService.deleteRole(roleId, context, new ResultHandler<Void>() {
                        @Override
                        public void onSuccess(Void result) {
                            editTextOp.setText("Successfully deleted Role");
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });
        } else if (id == R.id.nav_acl_privilege) {
            final EditText editTextUser = (EditText) findViewById(R.id.aclPrivilegeUser);
            final EditText editTextRole = (EditText) findViewById(R.id.aclPrivilegeRole);
            final EditText editTextResource = (EditText) findViewById(R.id.aclPrivilegeResource);
            final EditText editTextOperation = (EditText) findViewById(R.id.aclPrivilegeOperation);

            final EditText editTextCurrentUser = (EditText) findViewById(R.id.aclPrivilegeCurrentUser);
            final Button btnAssign = (Button) findViewById(R.id.aclPrivilegeAssign);
            final Button btnCreate = (Button) findViewById(R.id.aclPrivilegeCreate);
            final Button btnDelete = (Button) findViewById(R.id.aclPrivilegeDelete);
            final Button btnValidate = (Button) findViewById(R.id.aclPrivilegeCheck);
            final TextView editTextOp = (TextView) findViewById(R.id.aclPrivilegeOp);

            final UserService userService = getAclServiceFactory().getUserService();

            final PrivilegeService privilegeService = getAclServiceFactory().getPrivilegeService();

            btnAssign.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final String userId = editTextUser.getText().toString();
                    final String roleName = editTextRole.getText().toString();

                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    userService.assignRoleToUser(userId, roleName, context, new ResultHandler<UserRole>() {
                        @Override
                        public void onSuccess(UserRole result) {
                            editTextOp.setText("Successfully assigned Role: " + roleName + " to user: " + userId);
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });

            btnCreate.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final String roleName = editTextRole.getText().toString();
                    final String resourceName = editTextResource.getText().toString();
                    final String opName = editTextOperation.getText().toString();

                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    privilegeService.createPrivilege(roleName, resourceName, opName, context,
                            new ResultHandler<Privilege>() {
                        @Override
                        public void onSuccess(Privilege result) {
                            editTextOp.setText("Successfully created Privilege: " + roleName + ", " + resourceName
                             + ", " + opName);
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });

            btnDelete.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final String roleName = editTextRole.getText().toString();
                    final String resourceName = editTextResource.getText().toString();
                    final String opName = editTextOperation.getText().toString();

                    final AuthContext context = new AuthContext(editTextCurrentUser.getText().toString());

                    privilegeService.deletePrivilege(roleName, resourceName, opName, context,
                            new ResultHandler<Void>() {
                                @Override
                                public void onSuccess(Void result) {
                                    editTextOp.setText("Successfully deleted Privilege");
                                }

                                @Override
                                public void onFailure(DbError error) {
                                    editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                                }
                            });
                }
            });

            btnValidate.setOnClickListener(new View.OnClickListener() {

                @Override
                public void onClick(View v) {
                    editTextOp.setText("");
                    final String userId = editTextUser.getText().toString();
                    final String resourceName = editTextResource.getText().toString();
                    final String opName = editTextOperation.getText().toString();

                    privilegeService.isAllowed(userId, resourceName, opName, new ResultHandler<Boolean>() {
                        @Override
                        public void onSuccess(Boolean result) {
                            editTextOp.setText("Authorization result: " + result);
                        }

                        @Override
                        public void onFailure(DbError error) {
                            editTextOp.setText("Unsuccessful: " + error.getCode() + ", " + error.getMessage());
                        }
                    });
                }
            });
        }

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
    }
}
