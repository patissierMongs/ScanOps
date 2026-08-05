import {
  createAssetWorkbookSession,
  handleAssetWorkbookRequest,
} from "./assetWorkbookSession.js";


const session = createAssetWorkbookSession();

self.onmessage = (event) => {
  self.postMessage(handleAssetWorkbookRequest(session, event.data));
};
