import { getSession } from "next-auth/client";

import { verifyPassword, hashPassword } from "../../../lib/auth";
import { connectDatabase } from "../../../lib/db";

async function handler(req, res) {
  if (req.method !== "PATCH") {
    return res.status(400).json({ message: "Invalid request!" });
  }

  const session = await getSession({ req: req });
  if (!session) {
    return res.status(401).json({ message: "Unauthorized request!" });
  }

  const userEmail = session.user.email;
  const oldPassword = req.body.oldPassword;
  const newPassword = req.body.newPassword;

  if (newPassword.trim().length < 7) {
    return res.status(422).json({ message: "Invalid new password!" });
  }

  const client = await connectDatabase();
  const usersCollection = client.db().collection("users");

  const user = await usersCollection.findOne({ email: userEmail });

  if (!user) {
    await client.close();
    return res.status(404).json({ message: "User not found!" });
  }

  const isValid = await verifyPassword(oldPassword, user.password);
  if (!isValid) {
    await client.close();
    return res.status(403).json({ message: "Invalid old password!" });
  }

  const hashedPassword = await hashPassword(newPassword);

  await usersCollection.updateOne(
    { email: userEmail },
    { $set: { password: hashedPassword } }
  );

  await client.close();

  return res.status(200).json({ message: "Password updated successfully." });
}

export default handler;
