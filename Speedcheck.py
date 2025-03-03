import speedtest

def check_network_speed():
    try:
        print("🔄 Testing network speed... Please wait.")

        # Initialize speedtest
        st = speedtest.Speedtest()

        # Get the best server based on ping
        st.get_best_server()

        # Measure download speed
        download_speed = st.download() / 1_000_000  # Convert to Mbps

        # Measure upload speed
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps

        # Get ping latency
        ping_latency = st.results.ping

        # Print results
        print(f"📶 Download Speed: {download_speed:.2f} Mbps")
        print(f"📤 Upload Speed: {upload_speed:.2f} Mbps")
        print(f"⏳ Ping Latency: {ping_latency:.2f} ms")

    except Exception as e:
        print(f"❌ Error: {e}")

# Run speed test
check_network_speed()
