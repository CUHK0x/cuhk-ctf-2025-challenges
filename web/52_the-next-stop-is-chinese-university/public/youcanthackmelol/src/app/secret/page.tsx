export default function Page() {
  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center p-4">
      <div className="max-w-lg w-full p-8 border border-gray-700 rounded-lg">
        <h2 className="text-3xl font-bold mb-4 text-center">Secret Page</h2>
        <p className="text-center">
          Wow! No way you got here! This is a secret page that only the most
          skilled hackers can access.
          <br />
          Here is your flag:
          <br />
          <strong>{process.env.FLAG || "Try harder LOL"}</strong>
        </p>
      </div>
    </div>
  );
}
