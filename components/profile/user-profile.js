// import { useState, useEffect } from "react";
// import { getSession } from "next-auth/client";

import ProfileForm from "./profile-form";
import classes from "./user-profile.module.css";

function UserProfile() {
  // const [loading, setLoading] = useState(true);

  // useEffect(() => {
  //   getSession().then((session) => {
  //     if (!session) {
  //       window.location.href = "/auth";
  //     } else {
  //       setLoading(false);
  //     }
  //   });
  // }, []);

  // if (loading) {
  //   return <p className={classes.profile}>Loading....</p>;
  // }

  async function handlePasswordChange(passwordData) {
    const response = await fetch("/api/user/change-password", {
      method: "PATCH",
      body: JSON.stringify(passwordData),
      headers: {
        "Content-Type": "application/json",
      },
    });

    const data = await response.json();
    console.log(data);
  }

  return (
    <section className={classes.profile}>
      <h1>Your User Profile</h1>
      <ProfileForm onChangePassword={handlePasswordChange} />
    </section>
  );
}

export default UserProfile;
