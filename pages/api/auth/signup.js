import { hashPassword } from "../../../lib/auth";
import { connectDatabase, validateEmail } from "../../../lib/db";

async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(400).json({ message: "Invalid request!" });
  }

  const data = req.body;
  const { email, password } = data;

  if (
    !email ||
    !validateEmail(email) ||
    !password ||
    password.trim().length < 7
  ) {
    return res.status(422).json({ message: "Invalid input data" });
  }

  const client = await connectDatabase();
  const db = client.db();

  const existingUser = await db.collection("users").findOne({ email });
  if (existingUser) {
    await client.close();
    return res.status(400).json({ message: "User already exists" });
  }

  const hashedPassword = await hashPassword(password);

  const result = await db.collection("users").insertOne({
    email,
    password: hashedPassword,
  });

  await client.close();
  return res.status(201).json({ message: "Created user!" });
}

export default handler;
