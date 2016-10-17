package eu.itinn;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Porxy servlet for accessing remote API and correcting "Access-Control-Allow-Origin" header field.
 */
public class ProxyServlet extends HttpServlet {
	private static final Logger log = LoggerFactory.getLogger(ProxyServlet.class);

	private static final String ENVIRONMENT_JSON = "environment.json";
	private static final long serialVersionUID = 1L;
	private String remoteApi;
	private Set<String> allowOrigins = new HashSet<>();
	private SSLSocketFactory socketFactory;

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		boolean ok = true;

		// load configuration
		try (InputStream jsonIs = getClass().getClassLoader().getResourceAsStream(ENVIRONMENT_JSON)) {
			JSONObject conf = new JSONObject(new JSONTokener(jsonIs));
			remoteApi = conf.getString("remoteapi");
			log.info("Remote API initialized to '{}'", remoteApi);

			JSONArray allO = conf.getJSONArray("alloworigins");
			if (allO != null && allO.length() > 0) {
				for (int i = allO.length() - 1; i >= 0; i--) {
					allowOrigins.add(allO.getString(i));
				}
			}
			log.info("Access-Control-Allow-Origin for : '{}'", allowOrigins);

			// trust all certificates (even invalid)
			// NOTE: at some point we've seen expired certificate, it's probably already ok right now, but we leave this code it here (just for sure).
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				@Override
				public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				}

				@Override
				public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				}
			} };
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			// HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			socketFactory = sc.getSocketFactory();

		} catch (Exception ex) {
			log.error("Cannot get {} to load configuration .", ENVIRONMENT_JSON, ex);
			ok = false;
		}

		if (ok) {
			log.info("Proxy servlet successfuly configured.");
		}
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		try {
			String path = req.getPathInfo();
			String query = req.getQueryString();

			String url = remoteApi + path + (query != null ? "?" + query : "");

			// Get client's origin
			String clientOrigin = req.getHeader("origin");
			if (allowOrigins.contains(clientOrigin)) {
				resp.setHeader("Access-Control-Allow-Origin", clientOrigin);
			}

			// route / resend response
			copyRemote(url, resp);
		} catch (Exception e) {
			log.error("Unexpected server exception.", e);
			resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

		}

	}

	/**
	 * Copy ALL available data from one stream into another
	 */
	public static void copy(InputStream in, OutputStream out) throws IOException {
		ReadableByteChannel source = Channels.newChannel(in);
		WritableByteChannel target = Channels.newChannel(out);

		try {
			ByteBuffer buffer = ByteBuffer.allocate(16 * 1024);
			while (source.read(buffer) != -1) {
				buffer.flip(); // Prepare the buffer to be drained
				while (buffer.hasRemaining()) {
					target.write(buffer);
				}
				buffer.clear(); // Empty buffer to get ready for filling
			}
		} catch (Exception e) {
			log.error("Exception when copying stream: {}", e.getMessage(), e);
		}
		source.close();
		target.close();

	}

	/**
	 * Get stream from url (remote response) and copy to (local) response.
	 */
	public void copyRemote(String urlToRead, HttpServletResponse resp) throws Exception {

		// open remote url
		URL url = new URL(urlToRead);
		URLConnection urlConnection = url.openConnection();
		if (urlConnection instanceof HttpsURLConnection && socketFactory != null) {
			((HttpsURLConnection) urlConnection).setSSLSocketFactory(socketFactory);
		}

		// copy contenttype and length
		resp.setContentType(urlConnection.getContentType());
		resp.setContentLengthLong(urlConnection.getContentLengthLong());

		// copy streams
		copy(urlConnection.getInputStream(), resp.getOutputStream());
	}

}
