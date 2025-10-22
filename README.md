# dt-flux-test
to test flux helm controller

flux bootstrap github \
  --token-auth \
  --owner=rdwr-fimal \
  --repository=dt-flux-test \
  --branch=main \
  --path="./" \
  --personal
