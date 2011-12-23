/*
 * Copyright 2010, Nikhil Marathe <nsm.nikhil@gmail.com> All rights reserved.
 * See LICENSE for details
 */

#ifndef SASLJS_H
#define SASLJS_H

#include <map>
#include <string>

#include <gsasl.h>

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>

namespace sasljs {
class Session : public node::ObjectWrap
{
  public:
    static v8::Local<v8::FunctionTemplate> 
    Initialize ( v8::Handle<v8::Object> target );

  protected:
    static v8::Handle<v8::Value>
    New (const v8::Arguments& args);

    static v8::Handle<v8::Value> GetMechanisms( const v8::Arguments& args );
    static v8::Handle<v8::Value> Step( const v8::Arguments &args );
    static v8::Handle<v8::Value> GetSaslProperty( const v8::Arguments &args );
    static v8::Handle<v8::Value> SetSaslProperty( const v8::Arguments &args );

    static int Callback( Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop );

    Session( const char *realm, v8::Persistent<v8::Function> *cb );
    ~Session();

    Gsasl_session *m_session;

  private:
    v8::Persistent<v8::Function> *m_callback;
};

class ServerSession : public Session {
  public:
    static void
    Initialize ( v8::Handle<v8::Object> target );

  protected:
    static v8::Handle<v8::Value> Start( const v8::Arguments &args );
};

class ClientSession : public Session {
  public:
    static void
    Initialize ( v8::Handle<v8::Object> target );

  protected:
    static v8::Handle<v8::Value> Start( const v8::Arguments &args );
};

static Gsasl *ctx;
static std::map<std::string, Gsasl_property> property_strings;
static std::map<Gsasl_property, const char *> property_codes;
}

#endif
