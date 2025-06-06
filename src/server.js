const app = require('./app');
const { PORT} = require('./config/env');
const db = require('./config/db');

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
