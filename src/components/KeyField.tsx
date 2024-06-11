import {useState} from "react";

export default function KeyField({cypherKey, handleKeyChange}:{
    cypherKey:string,
    handleKeyChange: (e: React.ChangeEvent<HTMLInputElement>) => void }) {
    const [showKey, setShowKey] = useState(true);

    return(
        <div className="sm:col-span-4">
            <label htmlFor="username" className="block text-sm font-medium leading-6 text-gray-900">
                Key for Encryption and Decryption
            </label>
            <div className="mt-2">
                <div className="flex rounded-md shadow-sm ring-1 ring-inset ring-gray-300 focus-within:ring-2 focus-within:ring-inset focus-within:ring-green-600 sm:max-w-md px-2">
                    <input
                        type={showKey ? 'text' : 'password'}
                        value={cypherKey}
                        onChange={(e) => handleKeyChange(e)}
                        name="key"
                        id="key"
                        className="block flex-1 border-0 bg-transparent py-1.5 pl-1 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
                    />
                    <button
                        type="button"
                        onClick={()=>setShowKey((prevKey)=>!prevKey)}
                        className="focus:outline-none"
                    >
                        {showKey ? 'Hide' : 'Show'}
                    </button>
                </div>
            </div>
        </div>
    )
}