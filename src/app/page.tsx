"use client"
import {ArrowDownCircleIcon, PhotoIcon} from '@heroicons/react/24/solid'
import {
  useEffect,
  useState
} from "react";
import KeyField from "@/components/KeyField";
import readFileAsText from "@/server/readFileAsText";
import postFile from "@/server/postFile";
import Link from "next/link";


const types: Type[] = ["CTR", "CBC", "ECB"];
const modes: Mode[] = ["encrypt", "decrypt"];

export default function Home() {
  const [cypherKey, setCypherKey] = useState('0123456789ABCDEF');
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [type, setType] = useState<Type>("CTR");
  const [mode, setMode] = useState<Mode>("encrypt");

  const [responseFiles, setResponseFiles] = useState<UploadedFile[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [fileLinks, setFileLinks] = useState<ResponseFiles>([]);


  useEffect(() => {

    // Generate links for each file in responseFiles
    const links: ResponseFiles = responseFiles.map((file: any, index:number) => {
      const blob = new Blob([file.res], {type: 'text/plain'});
      const url = URL.createObjectURL(blob);
      return {name: file.name, url};
    });
    setFileLinks(links);

    return () => {
      links.forEach((link: { url: string; }) => URL.revokeObjectURL(link.url));
    };
  }, [responseFiles]);

  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    e.preventDefault();
    const fileList = e.target.files;
    if (fileList) {
      const files = Array.from(fileList);
      const newFiles: UploadedFile[] = [];
      for (const file of files) {
        try {
          const text = await readFileAsText(file);
          newFiles.push({
            name: file.name,
            size: file.size,
            text: text
          });
        } catch (error) {
          throw new Error(`Failed to read file: ${file.name}`)
        }
      }
      setUploadedFiles(prevFiles => [...prevFiles, ...newFiles]);
    }
  }

  async function handleSubmit() {
    if (uploadedFiles.length === 0){
      setError("Please upload a file");
      return;
    }
    if(cypherKey === "") {
      setError("Key is required");
      return;
    }
    if(cypherKey.length !== 16) {
      setError("Key must be 16 bytes long");
      return;
    }

    try {
      const response = await Promise.all(uploadedFiles.map(file => postFile(cypherKey, type, mode, file)));
      console.log(response)
      setResponseFiles(response);
    } catch (error) {
      setError(error as string);
      return;
    }
    setError(null);
  }

  function handleKeyChange (e: React.ChangeEvent<HTMLInputElement>) {
    e.preventDefault();
    setCypherKey(e.target.value);
  }

  function handleCancel() {
    setCypherKey("0123456789ABCDEF");
    setUploadedFiles([]);
    setMode("encrypt");
    setType("CTR");
    setError(null);
    setResponseFiles([]);
    setFileLinks([])
  }


  return (
      <div className="max-w-4xl mx-auto px-8 py-8">
        <h1 className="text-5xl font-bold">
          Szyfrowanie i <br/> Deszyfrowanie plików
        </h1>
        <form action={handleSubmit} className="bg-gray-50 p-4 rounded-lg mt-10">
          <div className="space-y-12">
            <div className="border-b border-gray-900/10 pb-12">
              <div className="grid grid-cols-1 gap-x-6 gap-y-8 sm:grid-cols-6">
                <KeyField cypherKey={cypherKey} handleKeyChange={handleKeyChange}/>
                <div className="sm:col-span-3">
                  <label htmlFor="location" className="block text-sm font-medium leading-6 text-gray-900">
                    Mode
                  </label>
                  <select
                      id="mode"
                      name="mode"
                      onChange={(e) => setMode(e.target.value as Mode)}
                      value={mode}
                      className="mt-2 block w-full bg-transparent rounded-md border-0 py-1.5 pl-3 pr-10 text-gray-900 ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-green-600 sm:text-sm sm:leading-6"
                  >
                    {modes.map((mode, index) => (
                        <option key={index}>{mode}</option>
                    ))}
                  </select>
                </div>

                <div className="sm:col-span-3">
                  <label htmlFor="location" className="block text-sm font-medium leading-6 text-gray-900">
                    Type
                  </label>
                  <select
                      id="type"
                      name="type"
                      value={type}
                      onChange={(e) => setType(e.target.value as Type)}
                      className="mt-2 block w-full rounded-md bg-transparent border-0 py-1.5 pl-3 pr-10 text-gray-900 ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-green-600 sm:text-sm sm:leading-6"
                  >
                    {types.map((type, index) => (
                        <option key={index}>{type}</option>
                    ))}
                  </select>
                </div>

                <div className="col-span-full">
                  <label htmlFor="cover-photo" className="block text-sm font-medium leading-6 text-gray-900">
                    Files
                  </label>
                  <div
                      className="mt-2 flex justify-center rounded-lg border border-dashed border-gray-900/25 px-6 py-10">
                    <div className="text-center">
                      <PhotoIcon className="mx-auto h-12 w-12 text-gray-300" aria-hidden="true"/>
                      <div className="mt-4 flex text-sm leading-6 text-gray-600">
                        <label
                            htmlFor="file-upload"
                            className="relative cursor-pointer rounded-md font-semibold text-green-600 focus-within:outline-none focus-within:ring-2 focus-within:ring-green-600 focus-within:ring-offset-2 hover:text-green-500"
                        >
                          <span>Upload a file</span>
                          <input id="file-upload" name="file-upload" type="file" accept=".txt"
                                 onChange={handleFileChange} multiple className="sr-only"/>
                        </label>
                        <p className="pl-1">or drag and drop</p>
                      </div>
                      <p className="text-xs leading-5 text-gray-600">.TXT</p>
                    </div>
                  </div>
                  {uploadedFiles.length > 0 && (
                      <div className="mt-4">
                        <p className="font-semibold text-gray-700">Uploaded files:</p>
                        <ul className="flex flex-col gap-y-5 mt-5">
                          {uploadedFiles.map((file, index) => (
                              <li key={index} className="flex justify-between items-center">
                                <div>
                                  <p>{file.name}</p>
                                  <p className="text-xs leading-5 text-gray-600">{file.size} bytes</p>
                                </div>
                              </li>
                          ))}
                        </ul>
                      </div>
                  )}
                </div>
              </div>
            </div>
          </div>
          <div className="mt-6 flex items-center justify-end gap-x-6">
            <span className="text-red-500">{error}</span>
            <button onClick={handleCancel} type="button" className="text-sm font-semibold leading-6 text-gray-900">
              Restart Form
            </button>
            <button
                type="submit"
                className="rounded-md bg-green-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-green-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-600"
            >
              Upload
            </button>
          </div>
        </form>
        {fileLinks.length > 0 && (
          <div className="bg-gray-50 p-4 rounded-lg mt-10">

                <div className="mt-4">
                  <p className="font-semibold text-gray-700">Download Converted files:</p>
                  <ul className="flex flex-col gap-y-5 mt-5">
                    {fileLinks.map((file: any, index: number) => (
                        <li key={index} className="flex justify-start items-center gap-x-4">
                          <ArrowDownCircleIcon className="h-6 w-6 text-green-600" aria-hidden="true"/>
                          <Link download={file.url} href={file.url} target="_blank">
                            <p>{file.name}</p>
                          </Link>
                        </li>
                    ))}
                  </ul>
                </div>
          </div>
        )}
      </div>

  );
}
