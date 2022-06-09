import { Length, IsNotEmpty, IsString } from "class-validator"
import { ApiProperty } from "@nestjs/swagger";

export class PassDto {
    @IsNotEmpty()
    @IsString()
    @Length(0,30)
    @ApiProperty({type: String, description: 'Password'})
    password: string

    @IsString()
    @ApiProperty({type: String, description: 'User unique id'})
    uuid: string
}