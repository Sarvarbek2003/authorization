import { IsEmail, Length, IsNotEmpty, IsString, IsNumber } from "class-validator"
import { ApiProperty } from "@nestjs/swagger";

export class AuthDto {
    @IsString()
    @ApiProperty({type: Number, description: 'Phone number'})
    phone: string
}