/*! \file   janus_rebroadcast.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Nick Chadwick <chadnickbok@gmail.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Rebroadcast plugin
 * \details  This is a simple application that implements a single feature:
 * it allows you to publish a stream with WebRTC and re-broadcast this
 * stream over RTMP.
 *
 * This application aims at showing how easy rebroadcasting to RTMP is, and
 * how WebRTC can be used as a viable RTMP replacement for broadcasting.
 *
 * The configuration process is quite easy: just choose where the RTMP
 * broadcast should be published to.
 *
 * The Rebroadcast API supports several requests, some of which are
 * synchronous and some asynchronous. There are some situations, though,
 * (invalid JSON, invalid request) which will always result in a
 * synchronous error response even for asynchronous requests.
 *
 * The \c broadcast and \c stop requests instead are both
 * asynchronous, which means you'll get a notification about their
 * success or failure in an event. \c broadcast asks the plugin to start
 * rebroadcasting a session and \c stop stops the session.
 *
 * An error would provide both an error code and a more verbose
 * description of the cause of the issue:
 *
\verbatim
{
	"rebroadcast" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 *
 * Coming to the asynchronous requests, \c broadcast has to be attached to
 * a JSEP offer (failure to do so will result in an error) and has to be
 * formatted as follows:
 *
\verbatim
{
	"request" : "broadcast",
	"rtmpurl" : "RTMP rebroadcast location (e.g., rtmp://servername:1935/streamkey)"
}
\endverbatim
 *
 * A successful management of this request will result in a \c broadcasting
 * event which will include the JSEP
 * answer to complete the setup of the associated PeerConnection to publish:
 *
\verbatim
{
	"rebroadcast" : "event",
	"result": {
		"status" : "broadcasting",
		"id":  <unique numeric ID>
	}
}
\endverbatim
 *
 * A \c stop request can interrupt the broadcasting process and tear the
 * associated PeerConnection down:
 *
\verbatim
{
	"request" : "stop",
}
\endverbatim
 *
 * This will result in a \c stopped status:
 *
\verbatim
{
	"rebroadcast" : "event",
	"result": {
		"status" : "stopped",
		"rtmpurl": "rtmp://servername:1935/streamkey"
	}
}
\endverbatim
 *
 * If the plugin detects a loss of the associated PeerConnection, whether
 * as a result of a \c stop request or otherwise, a
 * \c done result notification is triggered to inform the application
 * the rebroadcasting session is over:
 *
\verbatim
{
	"rebroadcast" : "event",
	"result": "done"
}
\endverbatim
 *
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <dirent.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_REBROADCAST_VERSION			1
#define JANUS_REBROADCAST_VERSION_STRING		"0.0.1"
#define JANUS_REBROADCAST_DESCRIPTION		"This is a trivial Rebroadcast plugin for Janus, to send WebRTC streams to RTMP."
#define JANUS_REBROADCAST_NAME				"JANUS Rebroadcast plugin"
#define JANUS_REBROADCAST_AUTHOR				"Nick Chadwick"
#define JANUS_REBROADCAST_PACKAGE			"janus.plugin.rebroadcast"

/* Plugin methods */
janus_plugin *create(void);
int janus_rebroadcast_init(janus_callbacks *callback, const char *config_path);
void janus_rebroadcast_destroy(void);
int janus_rebroadcast_get_api_compatibility(void);
int janus_rebroadcast_get_version(void);
const char *janus_rebroadcast_get_version_string(void);
const char *janus_rebroadcast_get_description(void);
const char *janus_rebroadcast_get_name(void);
const char *janus_rebroadcast_get_author(void);
const char *janus_rebroadcast_get_package(void);
void janus_rebroadcast_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_rebroadcast_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_rebroadcast_setup_media(janus_plugin_session *handle);
void janus_rebroadcast_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_rebroadcast_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_rebroadcast_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_rebroadcast_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_rebroadcast_hangup_media(janus_plugin_session *handle);
void janus_rebroadcast_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_rebroadcast_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_rebroadcast_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_rebroadcast_init,
		.destroy = janus_rebroadcast_destroy,

		.get_api_compatibility = janus_rebroadcast_get_api_compatibility,
		.get_version = janus_rebroadcast_get_version,
		.get_version_string = janus_rebroadcast_get_version_string,
		.get_description = janus_rebroadcast_get_description,
		.get_name = janus_rebroadcast_get_name,
		.get_author = janus_rebroadcast_get_author,
		.get_package = janus_rebroadcast_get_package,

		.create_session = janus_rebroadcast_create_session,
		.handle_message = janus_rebroadcast_handle_message,
		.setup_media = janus_rebroadcast_setup_media,
		.incoming_rtp = janus_rebroadcast_incoming_rtp,
		.incoming_rtcp = janus_rebroadcast_incoming_rtcp,
		.incoming_data = janus_rebroadcast_incoming_data,
		.slow_link = janus_rebroadcast_slow_link,
		.hangup_media = janus_rebroadcast_hangup_media,
		.destroy_session = janus_rebroadcast_destroy_session,
		.query_session = janus_rebroadcast_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_REBROADCAST_NAME);
	return &janus_rebroadcast_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter configure_parameters[] = {
	{"video-bitrate-max", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"video-keyframe-interval", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter broadcast_parameters[] = {
	{"rtmpurl", JSON_STRING, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_NONEMPTY}
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static GThread *watchdog;
static void *janus_rebroadcast_handler(void *data);

typedef struct janus_rebroadcast_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_rebroadcast_message;
static GAsyncQueue *messages = NULL;
static janus_rebroadcast_message exit_message;

typedef struct janus_rebroadcast_broadcast {
	guint64 id;			/* Rebroadcast unique ID */
	char *rtmpurl;			/* RTMP broadcast url */
	gboolean completed;	/* Whether this broadcast was completed or still going on */
	gint64 destroyed;	/* Lazy timestamp to mark broadcasts as destroyed */
	janus_mutex mutex;	/* Mutex for this broadcast */
} janus_rebroadcast_broadcast;
static GHashTable *broadcasts = NULL;
static janus_mutex broadcasts_mutex;

typedef struct janus_rebroadcast_session {
	janus_plugin_session *handle;
	gboolean active;
	gboolean firefox;	/* We send Firefox users a different kind of FIR */
	janus_rebroadcast_broadcast *broadcast;
	// TODO: RTMP Structure
	// janus_mutex rtmp_mutex;	/* Mutex to protect RTMP from race conditions */
	guint video_remb_startup;
	guint64 video_remb_last;
	guint64 video_bitrate;
	guint video_keyframe_interval; /* keyframe request interval (ms) */
	guint64 video_keyframe_request_last; /* timestamp of last keyframe request sent */
	gint video_fir_seq;
	volatile gint hangingup;
	gint64 destroyed;	/* Time at which this session was marked as destroyed */
} janus_rebroadcast_session;
static GHashTable *sessions;
static GList *old_sessions;
static janus_mutex sessions_mutex;

/* Helper to send RTCP feedback back to broadcasters, if needed */
void janus_rebroadcast_send_rtcp_feedback(janus_plugin_session *handle, int video, char *buf, int len);

static void janus_rebroadcast_message_free(janus_rebroadcast_message *msg)
{
	if (!msg || (msg == &exit_message))
	{
		return;
	}

	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if (msg->message) {
		json_decref(msg->message);
	}
	msg->message = NULL;
	if (msg->jsep) {
		json_decref(msg->jsep);
	}
	msg->jsep = NULL;

	g_free(msg);
}

/* SDP answer templates */
#define sdp_template \
		"v=0\r\n" \
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */ \
		"s=%s\r\n"							/* Recording playout id */ \
		"t=0 0\r\n" \
		"%s%s"								/* Audio and/or video m-lines */
#define sdp_a_template \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* Opus payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d opus/48000/2\r\n"		/* Opus payload type */
#define sdp_v_template \
		"m=video 1 RTP/SAVPF %d\r\n"		/* VP8 payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d VP8/90000\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d ccm fir\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d nack\r\n"				/* VP8 payload type */ \
		"a=rtcp-fb:%d nack pli\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d goog-remb\r\n"		/* VP8 payload type */


/* Error codes */
#define JANUS_REBROADCAST_ERROR_NO_MESSAGE			  411
#define JANUS_REBROADCAST_ERROR_INVALID_JSON		  412
#define JANUS_REBROADCAST_ERROR_INVALID_REQUEST	  413
#define JANUS_REBROADCAST_ERROR_INVALID_ELEMENT	  414
#define JANUS_REBROADCAST_ERROR_MISSING_ELEMENT	  415
#define JANUS_REBROADCAST_ERROR_INVALID_STATE	418
#define JANUS_REBROADCAST_ERROR_UNKNOWN_ERROR	499


/* Rebroadcast watchdog/garbage collector (sort of) */
void *janus_rebroadcast_watchdog(void *data);
void *janus_rebroadcast_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "Rebroadcast watchdog started\n");
	gint64 now = 0;
	while (g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping))
	{
		janus_mutex_lock(&sessions_mutex);

		/* Iterate on all the sessions */
		now = janus_get_monotonic_time();
		if (old_sessions != NULL)
		{
			GList *sl = old_sessions;
			JANUS_LOG(LOG_HUGE, "Checking %d old Rebroadcast sessions...\n", g_list_length(old_sessions));
			while (sl)
			{
				janus_rebroadcast_session *session = (janus_rebroadcast_session *)sl->data;
				if (!session)
				{
					sl = sl->next;
					continue;
				}

				if ((now - session->destroyed) >= 5*G_USEC_PER_SEC)
				{
					/* We're lazy and actually get rid of the stuff only after a few seconds */
					JANUS_LOG(LOG_VERB, "Freeing old Rebroadcast session\n");
					GList *rm = sl->next;
					old_sessions = g_list_delete_link(old_sessions, sl);
					sl = rm;
					session->handle = NULL;
					g_free(session);
					session = NULL;
					continue;
				}
				sl = sl->next;
			}
		}
		janus_mutex_unlock(&sessions_mutex);
		g_usleep(500000);
	}
	JANUS_LOG(LOG_INFO, "Rebroadcast watchdog stopped\n");
	return NULL;
}


/* Plugin implementation */
int janus_rebroadcast_init(janus_callbacks *callback, const char *config_path)
{
	if (g_atomic_int_get(&stopping))
	{
		/* Still stopping from before */
		return -1;
	}

	if (callback == NULL || config_path == NULL)
	{
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_REBROADCAST_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if (config != NULL)
	{
		janus_config_print(config);
	}

	/* Parse configuration */
	if (config != NULL)
	{
		// TODO: Parse config
		janus_config_destroy(config);
		config = NULL;
	}

	broadcasts = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	janus_mutex_init(&broadcasts_mutex);

	sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&sessions_mutex);
	messages = g_async_queue_new_full((GDestroyNotify) janus_rebroadcast_message_free);
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	g_atomic_int_set(&initialized, 1);

	/* Start the sessions watchdog */
	GError *error = NULL;
	watchdog = g_thread_try_new("rebroadcast watchdog", &janus_rebroadcast_watchdog, NULL, &error);
	if (error != NULL)
	{
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Rebroadcast watchdog thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}

	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("rebroadcast handler", janus_rebroadcast_handler, NULL, &error);
	if (error != NULL)
	{
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Rebroadcast handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_REBROADCAST_NAME);
	return 0;
}

void janus_rebroadcast_destroy(void) {
	if (!g_atomic_int_get(&initialized)) {
		return;
	}

	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if (handler_thread != NULL)
	{
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}

	if (watchdog != NULL)
	{
		g_thread_join(watchdog);
		watchdog = NULL;
	}

	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	sessions = NULL;
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_REBROADCAST_NAME);
}

int janus_rebroadcast_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_rebroadcast_get_version(void) {
	return JANUS_REBROADCAST_VERSION;
}

const char *janus_rebroadcast_get_version_string(void) {
	return JANUS_REBROADCAST_VERSION_STRING;
}

const char *janus_rebroadcast_get_description(void) {
	return JANUS_REBROADCAST_DESCRIPTION;
}

const char *janus_rebroadcast_get_name(void) {
	return JANUS_REBROADCAST_NAME;
}

const char *janus_rebroadcast_get_author(void) {
	return JANUS_REBROADCAST_AUTHOR;
}

const char *janus_rebroadcast_get_package(void) {
	return JANUS_REBROADCAST_PACKAGE;
}

void janus_rebroadcast_create_session(janus_plugin_session *handle, int *error)
{
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
	{
		*error = -1;
		return;
	}
	janus_rebroadcast_session *session = (janus_rebroadcast_session *)g_malloc0(sizeof(janus_rebroadcast_session));
	session->handle = handle;
	session->active = FALSE;
	session->firefox = FALSE;
	// TODO: janus_mutex_init(&session->rtmp_mutex);
	session->destroyed = 0;
	g_atomic_int_set(&session->hangingup, 0);
	session->video_remb_startup = 4;
	session->video_remb_last = janus_get_monotonic_time();
	session->video_bitrate = 1024 * 1024; 		/* This is 1mbps by default */
	session->video_keyframe_request_last = 0;
	session->video_keyframe_interval = 15000; 	/* 15 seconds by default */
	session->video_fir_seq = 0;
	handle->plugin_handle = session;

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_rebroadcast_destroy_session(janus_plugin_session *handle, int *error)
{
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
	{
		*error = -1;
		return;
	}

	janus_rebroadcast_session *session = (janus_rebroadcast_session *)handle->plugin_handle;
	if (!session)
	{
		JANUS_LOG(LOG_ERR, "No Rebroadcast session associated with this handle...\n");
		*error = -2;
		return;
	}

	janus_mutex_lock(&sessions_mutex);
	if (!session->destroyed)
	{
		JANUS_LOG(LOG_VERB, "Removing Rebroadcast session...\n");
		janus_rebroadcast_hangup_media(handle);
		session->destroyed = janus_get_monotonic_time();
		g_hash_table_remove(sessions, handle);
		/* Cleaning up and removing the session is done in a lazy way */
		old_sessions = g_list_append(old_sessions, session);
	}
	janus_mutex_unlock(&sessions_mutex);

	return;
}

json_t *janus_rebroadcast_query_session(janus_plugin_session *handle)
{
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
	{
		return NULL;
	}

	janus_rebroadcast_session *session = (janus_rebroadcast_session *)handle->plugin_handle;
	if (!session)
	{
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}

	/* In the echo test, every session is the same: we just provide some configure info */
	json_t *info = json_object();
	json_object_set_new(info, "type", json_string("rebroadcast"));
	json_object_set_new(info, "broadcast_id", json_integer(session->broadcast->id));
	json_object_set_new(info, "broadcast_rtmpurl", json_string(session->broadcast->rtmpurl));
	json_object_set_new(info, "destroyed", json_integer(session->destroyed));
	return info;
}

struct janus_plugin_result *janus_rebroadcast_handle_message(
	janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
	{
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	}

	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	if (message == NULL)
	{
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_REBROADCAST_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto plugin_response;
	}

	janus_rebroadcast_session *session = (janus_rebroadcast_session *)handle->plugin_handle;
	if (!session)
	{
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		error_code = JANUS_REBROADCAST_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "session associated with this handle...");
		goto plugin_response;
	}

	if (session->destroyed)
	{
		JANUS_LOG(LOG_ERR, "Session has already been destroyed...\n");
		error_code = JANUS_REBROADCAST_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been destroyed...");
		goto plugin_response;
	}

	if (!json_is_object(root))
	{
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_REBROADCAST_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto plugin_response;
	}

	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_REBROADCAST_ERROR_MISSING_ELEMENT, JANUS_REBROADCAST_ERROR_INVALID_ELEMENT);
	if (error_code != 0)
	{
		goto plugin_response;
	}

	json_t *request = json_object_get(root, "request");
	/* Some requests ('create' and 'destroy') can be handled synchronously */
	const char *request_text = json_string_value(request);
  if (!strcasecmp(request_text, "configure"))
	{
		JANUS_VALIDATE_JSON_OBJECT(root, configure_parameters,
			error_code, error_cause, TRUE,
			JANUS_REBROADCAST_ERROR_MISSING_ELEMENT, JANUS_REBROADCAST_ERROR_INVALID_ELEMENT);
		if (error_code != 0) {
			goto plugin_response;
		}

		json_t *video_bitrate_max = json_object_get(root, "video-bitrate-max");
		if (video_bitrate_max)
		{
			session->video_bitrate = json_integer_value(video_bitrate_max);
			JANUS_LOG(LOG_VERB, "Video bitrate has been set to %"SCNu64"\n", session->video_bitrate);
		}

		json_t *video_keyframe_interval= json_object_get(root, "video-keyframe-interval");
		if (video_keyframe_interval)
		{
			session->video_keyframe_interval = json_integer_value(video_keyframe_interval);
			JANUS_LOG(LOG_VERB, "Video keyframe interval has been set to %u\n", session->video_keyframe_interval);
		}

		response = json_object();
		json_object_set_new(response, "rebroadcast", json_string("configure"));
		json_object_set_new(response, "status", json_string("ok"));

		/* Return a success, and also let the client be aware of what changed, to allow crosschecks */
		json_t *settings = json_object();
		json_object_set_new(settings, "video-keyframe-interval", json_integer(session->video_keyframe_interval));
		json_object_set_new(settings, "video-bitrate-max", json_integer(session->video_bitrate));
		json_object_set_new(response, "settings", settings);

		goto plugin_response;
	}
	else if (!strcasecmp(request_text, "broadcast") || !strcasecmp(request_text, "stop"))
	{
		/* These messages are handled asynchronously */
		janus_rebroadcast_message *msg = g_malloc0(sizeof(janus_rebroadcast_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;

		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	}
	else
	{
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_REBROADCAST_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if (error_code == 0 && !response)
			{
				error_code = JANUS_REBROADCAST_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid response");
			}

			if (error_code != 0)
			{
				/* Prepare JSON error event */
				json_t *event = json_object();
				json_object_set_new(event, "rebroadcast", json_string("event"));
				json_object_set_new(event, "error_code", json_integer(error_code));
				json_object_set_new(event, "error", json_string(error_cause));
				response = event;
			}

			if (root != NULL) {
				json_decref(root);
			}

			if (jsep != NULL) {
				json_decref(jsep);
			}

			g_free(transaction);

			return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
		}

}

void janus_rebroadcast_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
	{
		return;
	}

	janus_rebroadcast_session *session = (janus_rebroadcast_session *)handle->plugin_handle;
	if (!session)
	{
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}

	if (session->destroyed)
	{
		return;
	}

	g_atomic_int_set(&session->hangingup, 0);
	/* Take note of the fact that the session is now active */
	session->active = TRUE;
}

void janus_rebroadcast_send_rtcp_feedback(janus_plugin_session *handle, int video, char *buf, int len)
{
	if (video != 1) {
		return;	/* We just do this for video, for now */
	}

	janus_rebroadcast_session *session = (janus_rebroadcast_session *)handle->plugin_handle;
	char rtcpbuf[24];

	/* Send a RR+SDES+REMB every five seconds, or ASAP while we are still
	 * ramping up (first 4 RTP packets) */
	gint64 now = janus_get_monotonic_time();
	guint64 elapsed = now - session->video_remb_last;
	gboolean remb_rampup = session->video_remb_startup > 0;

	if (remb_rampup || (elapsed >= 5 * G_USEC_PER_SEC))
	{
		guint64 bitrate = session->video_bitrate;

		if (remb_rampup)
		{
			bitrate = bitrate / session->video_remb_startup;
			session->video_remb_startup--;
		}

		/* Send a new REMB back */
		char rtcpbuf[24];
		janus_rtcp_remb((char *)(&rtcpbuf), 24, bitrate);
		gateway->relay_rtcp(handle, video, rtcpbuf, 24);

		session->video_remb_last = now;
	}

	/* Request a keyframe on a regular basis (every session->video_keyframe_interval ms) */
	elapsed = now - session->video_keyframe_request_last;
	guint64 interval = (session->video_keyframe_interval / 1000) * G_USEC_PER_SEC;

	if (elapsed >= interval)
	{
		/* Send both a FIR and a PLI, just to be sure */
		memset(rtcpbuf, 0, 20);
		janus_rtcp_fir((char *)&rtcpbuf, 20, &session->video_fir_seq);
		gateway->relay_rtcp(handle, video, rtcpbuf, 20);
		memset(rtcpbuf, 0, 12);
		janus_rtcp_pli((char *)&rtcpbuf, 12);
		gateway->relay_rtcp(handle, video, rtcpbuf, 12);
		session->video_keyframe_request_last = now;
	}
}

void janus_rebroadcast_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len)
{
	if (handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return;
	}

	if (gateway)
	{
		janus_rebroadcast_session *session = (janus_rebroadcast_session *)handle->plugin_handle;
		if (!session)
		{
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}

		if (session->destroyed)
		{
			return;
		}

		// TODO: rtmp publish frame
		// janus_rebroadcast_save_frame(video ? session->vrc : session->arc, buf, len);

		janus_rebroadcast_send_rtcp_feedback(handle, video, buf, len);
	}
}

void janus_rebroadcast_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len)
{
	if (handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
	{
		return;
	}
}

void janus_rebroadcast_incoming_data(janus_plugin_session *handle, char *buf, int len)
{
	if (handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
	{
		return;
	}
	/* FIXME We don't care */
}

void janus_rebroadcast_slow_link(janus_plugin_session *handle, int uplink, int video)
{
	if (handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
	{
		return;
	}

	janus_rebroadcast_session *session = (janus_rebroadcast_session *)handle->plugin_handle;
	if (!session || session->destroyed)
	{
		return;
	}

	json_t *event = json_object();
	json_object_set_new(event, "rebroadcast", json_string("event"));
	json_t *result = json_object();
	json_object_set_new(result, "status", json_string("slow_link"));

	/* What is uplink for the server is downlink for the client, so turn the tables */
	json_object_set_new(result, "current-bitrate", json_integer(session->video_bitrate));
	json_object_set_new(result, "uplink", json_integer(uplink ? 0 : 1));
	json_object_set_new(event, "result", result);
	gateway->push_event(session->handle, &janus_rebroadcast_plugin, NULL, event, NULL);
	json_decref(event);
}

void janus_rebroadcast_hangup_media(janus_plugin_session *handle)
{
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if (g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return;
	}

	janus_rebroadcast_session *session = (janus_rebroadcast_session *)handle->plugin_handle;
	if (!session)
	{
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}

	session->active = FALSE;
	if (session->destroyed)
	{
		return;
	}

	if (g_atomic_int_add(&session->hangingup, 1))
	{
		return;
	}

	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "rebroadcast", json_string("event"));
	json_object_set_new(event, "result", json_string("done"));
	int ret = gateway->push_event(handle, &janus_rebroadcast_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);

	/* FIXME Simulate a "stop" coming from the browser */
	janus_rebroadcast_message *msg = g_malloc0(sizeof(janus_rebroadcast_message));
	msg->handle = handle;
	msg->message = json_pack("{ss}", "request", "stop");
	msg->transaction = NULL;
	msg->jsep = NULL;
	g_async_queue_push(messages, msg);
}

/* Thread to handle incoming messages */
static void *janus_rebroadcast_handler(void *data)
{
	JANUS_LOG(LOG_VERB, "Joining Rebroadcast handler thread\n");
	janus_rebroadcast_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;

	while (g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping))
	{
		msg = g_async_queue_pop(messages);

		if (msg == NULL)
		{
			continue;
		}

		if (msg == &exit_message)
		{
			break;
		}

		if (msg->handle == NULL)
		{
			janus_rebroadcast_message_free(msg);
			continue;
		}

		janus_rebroadcast_session *session = NULL;
		janus_mutex_lock(&sessions_mutex);

		if (g_hash_table_lookup(sessions, msg->handle) != NULL)
		{
			session = (janus_rebroadcast_session *)msg->handle->plugin_handle;
		}

		janus_mutex_unlock(&sessions_mutex);

		if (!session)
		{
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_rebroadcast_message_free(msg);
			continue;
		}

		if (session->destroyed)
		{
			janus_rebroadcast_message_free(msg);
			continue;
		}

		/* Handle request */
		error_code = 0;
		root = NULL;
		if (msg->message == NULL)
		{
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_REBROADCAST_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}

		root = msg->message;
		/* Get the request first */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_REBROADCAST_ERROR_MISSING_ELEMENT, JANUS_REBROADCAST_ERROR_INVALID_ELEMENT);

		if (error_code != 0) {
			goto error;
		}

		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		json_t *result = NULL;
		char *sdp = NULL;

		if (!strcasecmp(request_text, "broadcast"))
		{
			if (!msg_sdp)
			{
				JANUS_LOG(LOG_ERR, "Missing SDP offer\n");
				error_code = JANUS_REBROADCAST_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing SDP offer");
				goto error;
			}

			JANUS_VALIDATE_JSON_OBJECT(root, broadcast_parameters,
				error_code, error_cause, TRUE,
				JANUS_REBROADCAST_ERROR_MISSING_ELEMENT, JANUS_REBROADCAST_ERROR_INVALID_ELEMENT);
			if (error_code != 0)
			{
				goto error;
			}

			json_t *rtmpurl = json_object_get(root, "rtmpurl");
			const char *rtmpurl_text = json_string_value(rtmpurl);

			guint64 id = 0;
			while (id == 0)
			{
				id = janus_random_uint64();
				if (g_hash_table_lookup(broadcasts, &id) != NULL)
				{
					/* Room ID already taken, try another one */
					id = 0;
				}
			}

			JANUS_LOG(LOG_VERB, "Starting new rebroadcast with ID %"SCNu64"\n", id);
			janus_rebroadcast_broadcast *rbc = (janus_rebroadcast_broadcast *)g_malloc0(sizeof(janus_rebroadcast_broadcast));
			rbc->id = id;
			rbc->rtmpurl = g_strdup(rtmpurl_text);
			rbc->completed = FALSE;
			janus_mutex_init(&rbc->mutex);

			// TODO: Setup RTMP

			if (strstr(msg_sdp, "m=audio"))
			{
				// TODO: Configure RTMP audio. Opus -> AAC?
			}

			if (strstr(msg_sdp, "m=video"))
			{
				// TODO: Configure RTMP video. VP8/VP9 -> H264?
			}

			session->broadcast = rbc;

			janus_mutex_lock(&broadcasts_mutex);
			g_hash_table_insert(broadcasts, janus_uint64_dup(rbc->id), rbc);
			janus_mutex_unlock(&broadcasts_mutex);

			/* We need to prepare an answer */
			int opus_pt = 0, vp8_pt = 0;
			opus_pt = janus_get_codec_pt(msg_sdp, "opus");
			JANUS_LOG(LOG_VERB, "Opus payload type is %d\n", opus_pt);
			vp8_pt = janus_get_codec_pt(msg_sdp, "vp8");
			JANUS_LOG(LOG_VERB, "VP8 payload type is %d\n", vp8_pt);
			char sdptemp[1024], audio_mline[256], video_mline[512];
			if (opus_pt > 0)
			{
				g_snprintf(audio_mline, 256, sdp_a_template,
					opus_pt,						/* Opus payload type */
					"recvonly",						/* Broadcasting is recvonly */
					opus_pt); 						/* Opus payload type */
			}
			else
			{
				audio_mline[0] = '\0';
			}

			if (vp8_pt > 0)
			{
				g_snprintf(video_mline, 512, sdp_v_template,
					vp8_pt,							/* VP8 payload type */
					"recvonly",						/* Broadcasting is recvonly */
					vp8_pt, 						/* VP8 payload type */
					vp8_pt, 						/* VP8 payload type */
					vp8_pt, 						/* VP8 payload type */
					vp8_pt, 						/* VP8 payload type */
					vp8_pt); 						/* VP8 payload type */
			}
			else
			{
				video_mline[0] = '\0';
			}

			g_snprintf(sdptemp, 1024, sdp_template,
				janus_get_real_time(),			/* We need current time here */
				janus_get_real_time(),			/* We need current time here */
				"broadcast",		            /* XXX: What is this? */
				audio_mline,					/* Audio m-line, if any */
				video_mline);					/* Video m-line, if any */
			sdp = g_strdup(sdptemp);
			JANUS_LOG(LOG_VERB, "Going to answer this SDP:\n%s\n", sdp);
			/* Done! */

			result = json_object();
			json_object_set_new(result, "status", json_string("broadcasting"));
			json_object_set_new(result, "id", json_integer(id));
		}
		else if(!strcasecmp(request_text, "stop"))
		{
			/* Stop the broadcast */
			session->active = FALSE;

			/*
			janus_mutex_lock(&session->rtmp_mutex);
			// TODO: Close RTMP rebroadcasting
			janus_mutex_unlock(&session->rtmp_mutex);
			*/

			/* Done! */
			result = json_object();
			json_object_set_new(result, "status", json_string("stopped"));
			json_object_set_new(result, "id", json_integer(session->broadcast->id));
		}
		else
		{
			JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
			error_code = JANUS_REBROADCAST_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
			goto error;
		}

		/* Any SDP to handle? */
		if (msg_sdp)
		{
			session->firefox = strstr(msg_sdp, "Mozilla") ? TRUE : FALSE;
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
		}

		/* Prepare JSON event */
		event = json_object();
		json_object_set_new(event, "rebroadcast", json_string("event"));
		if (result != NULL)
		{
			json_object_set_new(event, "result", result);
		}

		if (!sdp)
		{
			int ret = gateway->push_event(msg->handle, &janus_rebroadcast_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
		}
		else
		{
			const char *type = "answer";
			json_t *jsep = json_pack("{ssss}", "type", type, "sdp", sdp);
			/* How long will the gateway take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_rebroadcast_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n",
				res, janus_get_monotonic_time() - start);
			g_free(sdp);
			json_decref(event);
			json_decref(jsep);
		}

		janus_rebroadcast_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "rebroadcast", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_rebroadcast_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_rebroadcast_message_free(msg);
		}
	}

	JANUS_LOG(LOG_VERB, "Leaving Rebroadcast handler thread\n");
	return NULL;
}
