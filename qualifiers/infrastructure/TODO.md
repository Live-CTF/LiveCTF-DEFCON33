2024:
1. Change data model to:
  - submissions 1-* builds 1-* runs 1-1 output
  - team 1-* submissions
2. Reconsider auth
3. Switch to running builders and runners with podman in podman (rootless)
4. Add (better) web interface
5. Add better monitoring for builds and runs (Grafana?)

Future:
1. Use kubernetes for deployment and scaling
2. Make sure rabbitmq prometheus plugin is enabled
