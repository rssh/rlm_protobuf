/**
 * RLM_PROTOBUF
 * (C) GradSoft Ltd, Kiev. Ukraine
 **/
 
#include <rlm_protobuf_postconfig.h>

#include <pthread.h>

#include <freeradius-devel/radius.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/modules.h>

#include <curl/curl.h>

#include "vsa.pb-c.h"

#define AUTHORIZE  1
#define AUTHENTICATE 2
#define PREACCOUNT  3
#define ACCOUNT    4
#define CHECKSIM    5
#define POSTAUTH    6


typedef struct rlm_protobuf_t {
  char*  uri;
  char*  method;
  int    verbose;
  int    authenticate;
  int    authorize;
  int    preaccount;
  int    account;
  int    checksim;
  int    postauth;
  int    input_buffer_size;
  int    timeout;
} rlm_protobuf_t;

static const CONF_PARSER module_config[] = {
  { "url" , PW_TYPE_STRING_PTR, offsetof(rlm_protobuf_t,uri), NULL, NULL },
  { "method" , PW_TYPE_STRING_PTR, offsetof(rlm_protobuf_t,method), NULL, NULL },
  { "verbose", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,verbose), NULL, "no" },
  { "authenticate", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,authenticate), NULL, "yes" },
  { "authorize", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,authorize), NULL, "yes" },
  { "preaccount", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,preaccount), NULL, "yes" },
  { "account", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,account), NULL, "yes" },
  { "checksim", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,checksim), NULL, "yes" },
  { "postauth", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,postauth), NULL, "no" },
  { "input_buffer_size", PW_TYPE_INTEGER, offsetof(rlm_protobuf_t,input_buffer_size), NULL, "1024" },
  { "timeout", PW_TYPE_INTEGER, offsetof(rlm_protobuf_t,timeout), NULL, "30" },
  { NULL, -1, 0, NULL, NULL }
};


static pthread_key_t curl_key;
static pthread_once_t curl_once = PTHREAD_ONCE_INIT;

static void rlm_curl_make_key(void);
static CURL* rlm_curl_create_curlhandle(rlm_protobuf_t* instance);
static void rlm_curl_destroy_curlhandle(CURL*);


static void rlm_curl_make_key(void)
{
  pthread_key_create(&curl_key, rlm_curl_destroy_curlhandle);
}

static CURL* get_threadspecific_curl_handle(rlm_protobuf_t* instance)
{
  CURL* retval = (CURL*)pthread_getspecific(curl_key);
  if (retval==NULL) {
     retval=rlm_curl_create_curlhandle(instance);
     pthread_setspecific(curl_key,retval);
  }
  return retval;
}

static CURL* rlm_curl_create_curlhandle(rlm_protobuf_t* instance)
{
  CURL* retval = curl_easy_init();
  curl_easy_setopt(retval,CURLOPT_URL,instance->uri);
  if (instance->verbose) {
       curl_easy_setopt(retval,CURLOPT_VERBOSE,1);
 }
  return retval;
}

static void rlm_curl_destroy_curlhandle(CURL* handle)
{
 if (handle!=NULL) {
    curl_easy_cleanup(handle);
 }
}

static int rlm_protobuf_instantiate(CONF_SECTION* conf, void ** instance)
{
 rlm_protobuf_t* data;
 data = rad_malloc(sizeof(*data));
 if (!data) {
    return -1;
 }
 memset(data,0,sizeof(*data));

 if (cf_section_parse(conf, data, module_config) < 0) {
      free(data);
      return -1;
 }

 CURLcode rcode = curl_global_init(CURL_GLOBAL_ALL);
 if (rcode!=0) {
     radlog(L_ERR, "can't init curl %d",rcode);
     free(data);
     return -1;
 }

 *instance=data;

 pthread_once(&curl_once, rlm_curl_make_key);
 
 return 0;
}

static int rlm_protobuf_detach(void* instance)
{
 curl_global_cleanup();
 free(instance);
 return 0;
}


static void fill_protobuf_vp(Org__Freeradius__ValuePair* cvp, 
                             VALUE_PAIR* pair,
                             ProtobufCAllocator* allocator)
{
  cvp->attribute = pair->attribute;
  if (pair->vendor != 0) {
      cvp->has_vendor = 1;
      cvp->vendor = pair->vendor;
  }
  switch(pair->type) {
        case PW_TYPE_STRING:
               cvp->string_value = allocator->alloc(allocator->allocator_data,pair->length+1);
               strncpy(cvp->string_value,pair->vp_strvalue,pair->length+1);
               break;
         case PW_TYPE_INTEGER:
               cvp->has_int32_value = 1;
               cvp->int32_value = pair->vp_integer;
               break;
         case PW_TYPE_IPADDR:
               cvp->has_bytes_value = 1;
               cvp->bytes_value.len = 4;
               cvp->bytes_value.data = allocator->alloc(allocator->allocator_data,4);
               *cvp->bytes_value.data = htonl(pair->vp_ipaddr);
               break;
         case PW_TYPE_DATE:
               cvp->has_int32_value = 1;
               cvp->int32_value = pair->vp_date;
               break;
         case PW_TYPE_ABINARY:
         case PW_TYPE_OCTETS:
               cvp->has_bytes_value = 1;
               cvp->bytes_value.len = pair->length;
               cvp->bytes_value.data = allocator->alloc(allocator->allocator_data,pair->length);
               memcpy(cvp->bytes_value.data, pair->vp_strvalue, pair->length);
               break;
         case PW_TYPE_IFID:
               cvp->has_bytes_value = 1;
               cvp->bytes_value.len = sizeof(pair->vp_ifid);
               cvp->bytes_value.data = allocator->alloc(allocator->allocator_data,sizeof(pair->vp_ifid));
               memcpy(cvp->bytes_value.data, &(pair->vp_ifid), sizeof(pair->vp_ifid));
               break;
         case PW_TYPE_IPV6ADDR:
               //TODO: represent in network order ?
               cvp->has_bytes_value = 1;
               cvp->bytes_value.len = 16;
               cvp->bytes_value.data = allocator->alloc(allocator->allocator_data,16);
               memcpy(cvp->bytes_value.data, &(pair->vp_ipv6addr), 16);
               break;
         case PW_TYPE_IPV6PREFIX:
               cvp->has_bytes_value = 1;
               cvp->bytes_value.len = sizeof(pair->vp_ipv6prefix);
               cvp->bytes_value.data = allocator->alloc(allocator->allocator_data,cvp->bytes_value.len);
               memcpy(cvp->bytes_value.data, &(pair->vp_ipv6prefix), sizeof(pair->vp_ipv6prefix));
               break;
         case PW_TYPE_BYTE:
         case PW_TYPE_SHORT:
               cvp->has_int32_value = 1;
               cvp->int32_value = pair->vp_integer;
               break;
         case PW_TYPE_ETHERNET:
               cvp->has_bytes_value = 1;
               cvp->bytes_value.len = sizeof(pair->vp_ether);
               cvp->bytes_value.data = allocator->alloc(allocator->allocator_data,sizeof(pair->vp_ether));
               memcpy(cvp->bytes_value.data, &(pair->vp_ether), sizeof(pair->vp_ether));
               break;
         case PW_TYPE_SIGNED:
               cvp->has_sint32_value = 1;
               cvp->sint32_value = pair->vp_signed;
               break;
         case PW_TYPE_INTEGER64:
               cvp->has_int64_value = 1;
               cvp->int64_value = pair->vp_integer64;
               break;
         default:
               radlog(L_ERR,"unimplemented radius VSA type %d, skip",pair->type);
               break;
  }
}
                             

static Org__Freeradius__RequestData* 
                        code_protobuf_request( int method, 
                                      REQUEST* request,
                                      ProtobufCAllocator* allocator)
{
 RADIUS_PACKET* packet = request->packet;
 VALUE_PAIR* pair;
 Org__Freeradius__RequestData* request_data = 
                   allocator->alloc(allocator->allocator_data,
                                   sizeof(Org__Freeradius__RequestData));
 Org__Freeradius__RequestData tmp = ORG__FREERADIUS__REQUEST_DATA__INIT ;
 *request_data = tmp;
 request_data->state = method;
 request_data->n_vps = 0;
 if (packet!=NULL) {
   int n_pairs = 0;
   for(pair = packet->vps; pair != NULL; pair = pair->next) {
       ++n_pairs;
   }
   if (n_pairs > 0) {
      request_data->n_vps = n_pairs;
      request_data->vps = allocator->alloc(allocator->allocator_data,sizeof(Org__Freeradius__ValuePair*)*n_pairs);
   }
   int i=0;
   for(pair = packet->vps; pair != NULL; pair = pair->next) {
      Org__Freeradius__ValuePair* cvp = allocator->alloc(allocator->allocator_data,sizeof(Org__Freeradius__ValuePair));
      Org__Freeradius__ValuePair tmp = ORG__FREERADIUS__VALUE_PAIR__INIT;
      *cvp = tmp;
      request_data->vps[i++]=cvp;
      fill_protobuf_vp(cvp,pair,allocator);
   }
 }
 return request_data;
}


static VALUE_PAIR* create_radius_vp(Org__Freeradius__ValuePair* cvp,
                                    int* errflg)
{
  DICT_ATTR* attr = dict_attrbyvalue(cvp->attribute,
                                     (cvp->has_vendor ? cvp->vendor : 0));
  VALUE_PAIR* vp;
  if (attr==NULL) {
     radlog(L_ERR,"skipping unknown attribute %sd, %d",cvp->attribute,
                                     (cvp->has_vendor ? cvp->vendor : 0));
     return NULL;
  }

  vp = pairalloc(attr);
  *errflg=0;
  switch (attr->type) {
     case PW_TYPE_STRING:
          if (cvp->string_value!=NULL) {
            int maxLen = sizeof(vp->vp_strvalue);
            int sLen = strlen(cvp->string_value);
            if (sLen >= maxLen) {
               radlog(L_ERR,"too long string for attribute %s, truncate", attr->name);
               strncpy(vp->vp_strvalue,cvp->string_value,maxLen);
               vp->vp_strvalue[maxLen-1]='\0';
               vp->length=maxLen;
               *errflg=2;
            } else {
               strncpy(vp->vp_strvalue,cvp->string_value,maxLen);
               vp->length=sLen;
            }
          } else {
               radlog(L_ERR,"attribute %s must be string, have %d", attr->name, attr->type);
               *errflg=1;
          }
          break;
     case PW_TYPE_INTEGER:
     case PW_TYPE_SHORT:
     case PW_TYPE_BYTE:
          if (cvp->has_int32_value) {
              vp->vp_integer=cvp->int32_value;
              vp->length=sizeof(vp->vp_integer);
          } else {
             radlog(L_ERR,"attribute %s must be integer, have %d", attr->name, attr->type);
             *errflg=1;
          }
          break;
     case PW_TYPE_IPADDR:
          // be patient, at first check bytes, than string and int.
          if (cvp->has_bytes_value) {
            if (cvp->bytes_value.len ==4 ) {
              int32_t tmp;
              memcpy(&tmp,cvp->bytes_value.data,4);
              vp->vp_ipaddr = ntohl(tmp);
            } else {
              radlog(L_ERR,"invalid length of ip4 address in %s", attr->name);
              *errflg=1;
            }
          } else if (cvp->has_int32_value) {
            vp->vp_ipaddr = ntohl(cvp->int32_value);
          } else if (cvp->string_value!=NULL) {
            int rc = inet_pton(AF_INET, cvp->string_value, &(vp->vp_ipaddr));
            if (rc < 0) {
              char message[255];
              strerror_r(errno,message,255);
              radlog(L_ERR,"error during parsing ip_addr %s (%s)", attr->name,
                            message);
              *errflg=1;
            } else if (rc==0) {
              radlog(L_ERR,"invalid ip for %s (%s)", attr->name,cvp->string_value);
              *errflg=1;
            }
          } else {
             radlog(L_ERR,"attribute %s must be ipaddr", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_ABINARY:
     case PW_TYPE_OCTETS:
          if (cvp->has_bytes_value) {
            if(cvp->bytes_value.len > sizeof(vp->vp_strvalue)) {
               radlog(L_ERR,"too long byte sequence for attribute %s, truncate", attr->name);
               memcpy(vp->vp_strvalue, cvp->bytes_value.data, sizeof(vp->vp_strvalue));
               vp->length = sizeof(vp->vp_strvalue);
               *errflg=2;
            } else {
               memcpy(vp->vp_strvalue, cvp->bytes_value.data, sizeof(vp->vp_strvalue));
               vp->length = cvp->bytes_value.len;
            }
          } else {
             radlog(L_ERR,"attribute %s must be bytes", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_IFID:
          if (cvp->has_bytes_value) {
            if(cvp->bytes_value.len != sizeof(vp->vp_ifid)) {
               radlog(L_ERR,"incorrect ifid length for %s", attr->name);
               *errflg=1;
            } else {
               vp->length = sizeof(vp->vp_ifid);
               memcpy(&(vp->vp_ifid),cvp->bytes_value.data,sizeof(vp->vp_ifid));
            }
          } else {
             radlog(L_ERR,"attribute %s must be bytes", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_IPV6ADDR:
          if (cvp->has_bytes_value) {
            if (cvp->bytes_value.len == 16 ) {
               memcpy(&(vp->vp_ipv6addr),cvp->bytes_value.data, 16);
               vp->length=16;
            } else {
              radlog(L_ERR,"invalid length of ip6 address in %s", attr->name);
              *errflg=1;
            }
          } else if (cvp->string_value!=NULL) {
            int rc = inet_pton(AF_INET6, cvp->string_value, &(vp->vp_ipv6addr));
            if (rc < 0) {
              char message[255];
              strerror_r(errno,message,255);
              radlog(L_ERR,"error during parsing ip_addr %s (%s)", attr->name,
                            message);
              *errflg=1;
            } else if (rc==0) {
              radlog(L_ERR,"invalid ip for %s (%s)", attr->name, cvp->string_value);
              *errflg=1;
            } 
          } else {
              radlog(L_ERR,"reply: invalid type for ip6 address in %s", attr->name);
              *errflg=1;
          }
          break;
     case PW_TYPE_ETHERNET:
          if (cvp->has_bytes_value) {
            if (cvp->bytes_value.len == sizeof(vp->vp_ether)) {
              memcpy(vp->vp_ether,cvp->bytes_value.data, sizeof(vp->vp_ether));
              vp->length=sizeof(vp->vp_ether);
            } else {
              radlog(L_ERR,"invalid length of ether address in %s", attr->name);
              *errflg=1;
            }
          } else {
            radlog(L_ERR,"reply: invalid type for ether address in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_SIGNED:
          if (cvp->has_sint32_value) {
            vp->vp_signed = cvp->sint32_value;
            vp->length=sizeof(vp->vp_signed);
          } else {
            radlog(L_ERR,"reply: invalid type for signed attr in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_INTEGER64:
          if (cvp->has_int64_value) {
            vp->vp_integer64 = cvp->int64_value;
            vp->length=sizeof(vp->vp_integer64);
          } else {
            radlog(L_ERR,"reply: invalid type for integer64 attr in %s", attr->name);
            *errflg=1;
          }
          break;
     default:
         radlog(L_ERR,"reply: uninmplemented VSA type for %s", attr->name);
  }
  
  return vp;
}

static int adopt_protobuf_reply(int method,
                                Org__Freeradius__RequestDataReply* rdr, 
                                REQUEST* request
                               )
{
  int retval = rdr->has_allow ? 
                  (rdr->allow ? RLM_MODULE_OK : RLM_MODULE_REJECT) 
                  : RLM_MODULE_OK ;
  int i=0;
  if  (rdr->error_message!=NULL) {
     radlog(L_ERR,"error from protoserver: %s",rdr->error_message);
     return RLM_MODULE_INVALID;
  }
  
  for(i=0; i < rdr->n_actions; ++i) {
     int errflg=0;
     Org__Freeradius__ValuePairAction* action = rdr->actions[i]; 
     Org__Freeradius__ValuePair* cvp = action->vp; 
     if (action->op == ORG__FREERADIUS__VALUE_PAIR_OP__REMOVE) {
         pairdelete(&(request->reply->vps),cvp->attribute,
                                           cvp->has_vendor ? cvp->vendor : 0 );
     } else {
       VALUE_PAIR* vp = create_radius_vp(cvp,&errflg);
       if (vp!=NULL) {
         if (errflg==0 || errflg==2) {
           /* some attributes must be inserted to request->config-items, 
            * not reply
            */
           if (method==AUTHORIZE
              &&(  vp->attribute==PW_AUTH_TYPE
                 ||vp->attribute==PW_CLEARTEXT_PASSWORD
                )
              ) {
             if (action->op == ORG__FREERADIUS__VALUE_PAIR_OP__REPLACE) {
                pairreplace(&(request->config_items), vp);
             } else {
                pairadd(&(request->config_items), vp);
             }
           } else {
             if (action->op == ORG__FREERADIUS__VALUE_PAIR_OP__REPLACE) {
                pairreplace(&(request->reply->vps),vp);
             } else {
                pairadd(&(request->reply->vps),vp);
             }
           }
         } else {
           /* removed incorrect. */
           pairfree(&vp);
         }
       } else {
         /* incorrect attribute: just skip. */
       }
     }
  }

  return retval; 
}

struct BufferWithAllocator
{
 ProtobufCBufferSimple buffer;
 int                   idx;
 ProtobufCAllocator* allocator;
};
typedef struct BufferWithAllocator  BufferWithAllocator;

static size_t rlm_protobuf_read_function( void *ptr, 
                                          size_t size, 
                                          size_t nmemb, 
                                          void *userdata)
{
 BufferWithAllocator* pba = (BufferWithAllocator*)userdata;
 size_t bytesRequired = size*nmemb;
 size_t bytesLeft = (size_t)(pba->buffer.len - pba->idx);
 size_t bytesToTransfer = (bytesLeft > bytesRequired ? bytesRequired 
                                                     : bytesLeft);
 memcpy(ptr,pba->buffer.data+pba->idx,bytesToTransfer);
 pba->idx += bytesToTransfer;
 return bytesToTransfer;
}

size_t rlm_protobuf_write_function( char *ptr, 
                                    size_t size, 
                                    size_t nmemb, 
                                    void *userdata)
{
 BufferWithAllocator* pba = (BufferWithAllocator*)userdata;
 size_t nBytes = size*nmemb;
 (pba->buffer.base.append)(&pba->buffer.base,nBytes,ptr);
 return nBytes;
}


static int do_protobuf_curl_call(rlm_protobuf_t* instance, int method, REQUEST* request)
{
 CURL* handle = get_threadspecific_curl_handle(instance);
 CURLcode rc;
 int retval;
 struct BufferWithAllocator rba = {
    /*PROTOBUF_C_BUFFER_SIMPLE_INIT({}),
     { 
     {*/ protobuf_c_buffer_simple_append /*}*/, 
      0, 0, NULL , 0 
    /*}*/,
    0,
    &protobuf_c_default_allocator
 };
 struct BufferWithAllocator wba = {
    /*PROTOBUF_C_BUFFER_SIMPLE_INIT({}),
     {
       {*/ protobuf_c_buffer_simple_append /*}*/, 
       0, 0, NULL , 0 
    /*}*/,
    0,
    &protobuf_c_default_allocator
 };
 char errbuff[CURL_ERROR_SIZE];
 Org__Freeradius__RequestData* proto_request = 
         code_protobuf_request(method,request, &protobuf_c_default_allocator);
                                                         
 rba.buffer.alloced = org__freeradius__request_data__get_packed_size(proto_request);
 rba.buffer.data = rba.allocator->alloc(rba.allocator->allocator_data,rba.buffer.alloced);
 rba.buffer.must_free_data=1;
 org__freeradius__request_data__pack_to_buffer(proto_request, 
                                              & rba.buffer.base);

 wba.buffer.alloced = 1024;
 wba.buffer.data = wba.allocator->alloc(wba.allocator->allocator_data,wba.buffer.alloced);
 wba.buffer.must_free_data=1;

 curl_easy_setopt(handle, CURLOPT_UPLOAD, 1);
 curl_easy_setopt(handle, CURLOPT_INFILESIZE, rba.buffer.len);
 curl_easy_setopt(handle, CURLOPT_READFUNCTION, rlm_protobuf_read_function);
 curl_easy_setopt(handle, CURLOPT_READDATA, &rba);
 curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, rlm_protobuf_write_function);
 curl_easy_setopt(handle, CURLOPT_WRITEDATA, &wba);

 curl_easy_setopt(handle,CURLOPT_ERRORBUFFER,errbuff);
 rc=curl_easy_perform(handle);
 if (rc!=0) {
   radlog(L_ERR,"%s",errbuff);
   curl_easy_cleanup(handle);
   pthread_setspecific(curl_key,NULL);
   retval = RLM_MODULE_INVALID;
 }else {
   retval=RLM_MODULE_NOOP;
 }
 if (instance->verbose) {
   radlog(L_DBG,"received:\n%s",wba.buffer.len);
 }
 org__freeradius__request_data__free_unpacked(proto_request,rba.allocator);
 rba.allocator->free(rba.allocator->allocator_data,rba.buffer.data);
 if (rc==0) {
    // i. e. whe have no errors in curl
    //
    Org__Freeradius__RequestDataReply* proto_reply = 
       org__freeradius__request_data_reply__unpack(wba.allocator,
                                                   wba.buffer.len,
                                                   wba.buffer.data);

    retval = adopt_protobuf_reply(method, proto_reply, request); 
    org__freeradius__request_data_reply__free_unpacked(
                                                proto_reply,wba.allocator);
    wba.allocator->free(wba.allocator->allocator_data, wba.buffer.data);
 } else {
    if (wba.buffer.data!=NULL) {
       wba.allocator->free(wba.allocator->allocator_data, wba.buffer.data);
    }
 }
 return retval;
}

static int rlm_protobuf_authenticate(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_autheinticate");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->authenticate) {
   return do_protobuf_curl_call(tinstance, AUTHENTICATE, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

static int rlm_protobuf_authorize(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_authorize");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->authorize) {
   return do_protobuf_curl_call(tinstance, AUTHORIZE, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

static int rlm_protobuf_preaccount(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_preaccount");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->preaccount) {
   return do_protobuf_curl_call(tinstance, PREACCOUNT, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}


static int rlm_protobuf_account(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_account");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->account) {
   return do_protobuf_curl_call(tinstance, ACCOUNT, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

static int rlm_protobuf_checksim(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_checksim");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->checksim) {
   return do_protobuf_curl_call(tinstance, CHECKSIM, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

static int rlm_protobuf_postauth(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_postauth");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->postauth) {
   return do_protobuf_curl_call(tinstance, POSTAUTH, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

module_t rlm_protobuf = {
 RLM_MODULE_INIT,
 "protobuf",
 RLM_TYPE_THREAD_SAFE,
 rlm_protobuf_instantiate,
 rlm_protobuf_detach,
 {
   rlm_protobuf_authenticate,
   rlm_protobuf_authorize,
   rlm_protobuf_preaccount,
   rlm_protobuf_account,
   rlm_protobuf_checksim,  /* checksim */
   NULL,  /* pre-proxy */
   NULL, /* post-proxy */
   rlm_protobuf_postauth  /* post-auth */
 }
};


