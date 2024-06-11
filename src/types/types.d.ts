

declare global {
    type UploadedFile = {
        name: string;
        size: number;
        text: string;
    };
    type Type = "CTR" | "CBC" | "ECB";
    type Mode = "encrypt" | "decrypt";
    type ResponseFiles = {
        name: string, url:string
    }[]

}
export default {}