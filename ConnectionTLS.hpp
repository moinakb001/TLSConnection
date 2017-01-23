#include <net/tcp/connection.hpp>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <internal/refcount.h>
struct bio_st {
    const BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
    BIO_callback_fn callback;
    BIO_callback_fn_ex callback_ex;
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;    /* used by filter BIOs */
    struct bio_st *prev_bio;    /* used by filter BIOs */
    CRYPTO_REF_COUNT references;
    uint64_t num_read;
    uint64_t num_write;
    CRYPTO_EX_DATA ex_data;
    CRYPTO_RWLOCK *lock;
};

namespace net{
    namespace tcp{
        
        class ConnectionTLS:public Connection::Translator{
            public:
                ConnectionTLS(Connection_ptr _ptr):Connection::Translator(_ptr){
                    
                    st=(TLS_UNAUTH);
                    cSSL = SSL_new(ctx);
                    rbio = BIO_new(BIO_s_mem());
                    wbio = BIO_new(BIO_s_mem());
                    SSL_set_bio(cSSL,rbio,wbio);
                    BIO_set_callback_arg(wbio,(char *)this);
                    BIO_set_callback(wbio,[](BIO * io, auto cmd, auto argp, auto argi, auto, auto ret){
                    
                        if(cmd==(BIO_CB_WRITE)){
                            std::cout <<argi;
                            auto callback=(ConnectionTLS *)io->cb_arg;
                            auto buffer = new_shared_buffer(argi);
                            memcpy(buffer.get(), argp, argi);
                            callback->writeCb()({std::move(buffer), (size_t)argi, true},[](auto){});
                        }
                        return ret;
                    });
                }
            private:
                using ConnectCallback         = delegate<void(Connection_ptr self)>;
                using ReadCallback            = delegate<void(buffer_t, size_t)>;
                enum State
                {
                    TLS_UNAUTH,
                    TLS_WRITEABLE
                };
                State st;
                SSL * cSSL;
                BIO * rbio;
                BIO * wbio;
                void on_connect() override { 
                    SSL_connect(cSSL);
                    ptr->on_read(1024, [](auto,auto){});
                }
                void on_read(buffer_t buf, size_t sz) override {
                    BIO_write(rbio,&(*buf),sz);
                    if (st==TLS_UNAUTH) {
                        SSL_do_handshake(cSSL);
                        if(SSL_is_init_finished(cSSL)){
                            st=TLS_WRITEABLE;
                            connectCb()(ptr);
                        }
                    }
                    if(st==TLS_WRITEABLE){
                        auto numRead=SSL_read(cSSL,&(*buf),sz);
                        readCb()(buf,numRead);
                    }

                    
                }
                void on_write(WriteBuffer&& buffer, Connection::WriteCallback callback) override{

                    SSL_write(cSSL, buffer.buffer.get(), buffer.length());
                    
                }
                static void InitializeSSL()
                {
                    SSL_load_error_strings();
                    SSL_library_init();
                    OpenSSL_add_all_algorithms();
                }

                static void DestroySSL()
                {
                    ERR_free_strings();
                    EVP_cleanup();
                }

                static void ShutdownSSL(SSL * ssl)
                {
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                }
                static SSL_CTX * getSslCtx(){
                    InitializeSSL();
                    auto sslop = SSL_CTX_new( TLS_client_method());
                    SSL_CTX_set_verify(sslop,SSL_VERIFY_NONE,[](int,X509_STORE_CTX *)->int{return 1;});
                    return sslop;
                }
                static SSL_CTX * ctx;
    
                
                

        };
        SSL_CTX * ConnectionTLS::ctx=ConnectionTLS::getSslCtx();
        
    }
    

}