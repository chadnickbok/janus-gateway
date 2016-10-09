// We make use of this 'server' variable to provide the address of the
// REST Janus API. By default, in this example we assume that Janus is
// co-located with the web server hosting the HTML pages but listening
// on a different port (8088, the default for HTTP in Janus), which is
// why we make use of the 'window.location.hostname' base address. Since
// Janus can also do HTTPS, and considering we don't really want to make
// use of HTTP for Janus if your demos are served on HTTPS, we also rely
// on the 'window.location.protocol' prefix to build the variable, in
// particular to also change the port used to contact Janus (8088 for
// HTTP and 8089 for HTTPS, if enabled).
// In case you place Janus behind an Apache frontend (as we did on the
// online demos at http://janus.conf.meetecho.com) you can just use a
// relative path for the variable, e.g.:
//
// 		var server = "/janus";
//
// which will take care of this on its own.
//
//
// If you want to use the WebSockets frontend to Janus, instead, you'll
// have to pass a different kind of address, e.g.:
//
// 		var server = "ws://" + window.location.hostname + ":8188";
//
// Of course this assumes that support for WebSockets has been built in
// when compiling the gateway. WebSockets support has not been tested
// as much as the REST API, so handle with care!
//
//
// If you have multiple options available, and want to let the library
// autodetect the best way to contact your gateway (or pool of gateways),
// you can also pass an array of servers, e.g., to provide alternative
// means of access (e.g., try WebSockets first and, if that fails, fall
// back to plain HTTP) or just have failover servers:
//
//		var server = [
//			"ws://" + window.location.hostname + ":8188",
//			"/janus"
//		];
//
// This will tell the library to try connecting to each of the servers
// in the presented order. The first working server will be used for
// the whole session.
//
var server = null;
if (window.location.protocol === 'http:') {
	server = "http://" + window.location.hostname + ":8088/janus";
} else {
	server = "https://" + window.location.hostname + ":8089/janus";
}

var janus = null;
var rebroadcast = null;
var started = false;
var spinner = null;
var bandwidth = 1024 * 1024;

var rtmpurl = null;
var broadcasting = false;

$(document).ready(function() {
	// Initialize the library (all console debuggers enabled)
	Janus.init({debug: "all", callback: function() {
		// Use a button to start the demo
		$('#start').click(function() {
			if (started) {
				return;
			}
			started = true;
			$(this).attr('disabled', true).unbind('click');
			// Make sure the browser supports WebRTC
			if(!Janus.isWebrtcSupported()) {
				bootbox.alert("No WebRTC support... ");
				return;
			}
			// Create session
			janus = new Janus(
				{
					server: server,
					success: function() {
						// Attach to rebroadcast plugin
						janus.attach(
							{
								plugin: "janus.plugin.rebroadcast",
								success: function(pluginHandle) {
									$('#details').remove();
									rebroadcast = pluginHandle;
									Janus.log("Plugin attached! (" + rebroadcast.getPlugin() + ", id=" + rebroadcast.getId() + ")");
									// Prepare the rtmpurl prompt
									$('#rebroadcast').removeClass('hide').show();
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											janus.destroy();
										});
								},
								error: function(error) {
									Janus.error("  -- Error attaching plugin...", error);
									bootbox.alert("  -- Error attaching plugin... " + error);
								},
								consentDialog: function(on) {
									Janus.debug("Consent dialog should be " + (on ? "on" : "off") + " now");
									if(on) {
										// Darken screen and show hint
										$.blockUI({
											message: '<div><img src="up_arrow.png"/></div>',
											css: {
												border: 'none',
												padding: '15px',
												backgroundColor: 'transparent',
												color: '#aaa',
												top: '10px',
												left: (navigator.mozGetUserMedia ? '-100px' : '300px')
											} });
									} else {
										// Restore screen
										$.unblockUI();
									}
								},
								webrtcState: function(on) {
									Janus.log("Janus says our WebRTC PeerConnection is " + (on ? "up" : "down") + " now");
									$("#videobox").parent().unblock();
								},
								onmessage: function(msg, jsep) {
									Janus.debug(" ::: Got a message :::");
									Janus.debug(JSON.stringify(msg));
									var result = msg["result"];
									if (result !== null && result !== undefined) {
										if (result["status"] !== undefined && result["status"] !== null) {
											var event = result["status"];
											if (event === 'broadcasting') {
												// Got an ANSWER to our broadcasting OFFER
												if (jsep !== null && jsep !== undefined) {
													rebroadcast.handleRemoteJsep({jsep: jsep});
												}
											} else if (event === 'slow_link') {
												var uplink = result["uplink"];
												if (uplink !== 0) {
													// Janus detected issues when receiving our broadcast, let's slow down
													bandwidth = parseInt(bandwidth / 1.5);
													rebroadcast.send({
														'message': {
															'request': 'configure',
															'video-bitrate-max': bandwidth, // Reduce the bitrate
															'video-keyframe-interval': 15000 // Keep the 15 seconds key frame interval
														}
													});
												}
											} else if (event === 'stopped') {
												Janus.log("Session has stopped!");
												bootbox.alert("Rebroadcast completed.");
												// FIXME Reset status
												$('#videobox').empty();
												$('#video').hide();
												broadcasting = false;
												rebroadcast.hangup();
												$('#broadcast').removeAttr('disabled').click(startBroadcasting);
											}
										}
									} else {
										// FIXME Error?
										var error = msg["error"];
										bootbox.alert(error);
										// FIXME Reset status
										$('#videobox').empty();
										$('#video').hide();
										broadcasting = false;
										rebroadcast.hangup();
										$('#broadcast').removeAttr('disabled').click(startBroadcasting);
									}
								},
								onlocalstream: function(stream) {
									if (broadcasting === true) {
										return;
									}
									Janus.debug(" ::: Got a local stream :::");
									Janus.debug(JSON.stringify(stream));
									$('#videotitle').html("Broadcasting...");
									$('#stop').unbind('click').click(stop);
									$('#video').removeClass('hide').show();
									if ($('#thevideo').length === 0) {
										$('#videobox').append('<video class="rounded centered" id="thevideo" width=320 height=240 autoplay muted="muted"/>');
									}
									Janus.attachMediaStream($('#thevideo').get(0), stream);
									$("#thevideo").get(0).muted = "muted";
									$("#videobox").parent().block({
										message: '<b>Publishing...</b>',
										css: {
											border: 'none',
											backgroundColor: 'transparent',
											color: 'white'
										}
									});
								},
								oncleanup: function() {
									Janus.log(" ::: Got a cleanup notification :::");
									// FIXME Reset status
									$('#waitingvideo').remove();
									if (spinner !== null && spinner !== undefined) {
										spinner.stop();
									}
									spinner = null;
									$('#videobox').empty();
									$("#videobox").parent().unblock();
									$('#video').hide();
									broadcasting = false;
									$('#broadcast').removeAttr('disabled').click(startBroadcasting);
								}
							});
					},
					error: function(error) {
						Janus.error(error);
						bootbox.alert(error, function() {
							window.location.reload();
						});
					},
					destroyed: function() {
						window.location.reload();
					}
				});
		});
	}});
});

function startBroadcasting() {
	if (broadcasting) {
		return;
	}
	// Start broadcasting
	broadcasting = true;
	bootbox.prompt("Insert RTMP rebroadcast URI (e.g., rtmp://servername:1935/streamkey)", function(result) {
		if (result === null || result === undefined) {
			broadcasting = false;
			return;
		}
		rtmpurl = result;
		$('#broadcast').unbind('click').attr('disabled', true);

		// bitrate and keyframe interval can be set at any time:
		// before, after, during broadcasting
		rebroadcast.send({
			'message': {
				'request': 'configure',
				'video-bitrate-max': bandwidth, // a quarter megabit
				'video-keyframe-interval': 15000 // 15 seconds
			}
		});

		rebroadcast.createOffer(
			{
				// By default, it's sendrecv for audio and video...
				success: function(jsep) {
					Janus.debug("Got SDP!");
					Janus.debug(jsep);
					var body = { "request": "rebroadcast", "rtmpurl": rtmpurl };
					rebroadcast.send({"message": body, "jsep": jsep});
				},
				error: function(error) {
					Janus.error("WebRTC error...", error);
					bootbox.alert("WebRTC error... " + error);
					rebroadcast.hangup();
				}
			});
	});
}

function stop() {
	// Stop broadcasting
	$('#stop').unbind('click');
	var stop = { "request": "stop" };
	rebroadcast.send({"message": stop});
	rebroadcast.hangup();
}
