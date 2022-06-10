import { IsEmail, Length, IsNotEmpty, IsString, IsNumber } from "class-validator"
import { ApiProperty } from "@nestjs/swagger";

export class VerifyDto {
    @IsString()
    @ApiProperty({type: String, description: 'Verify code'})
    verify: string

    @IsString()
    @Length(0,6)
    @ApiProperty({type: String, description: 'Sms code'})
    smsCode: string

}