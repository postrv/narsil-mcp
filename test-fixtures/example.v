// Verilog example file for narsil-xref testing

// Simple counter module
module counter(
    input wire clk,
    input wire reset,
    input wire enable,
    output reg [7:0] count
);
    always @(posedge clk or posedge reset) begin
        if (reset)
            count <= 8'b0;
        else if (enable)
            count <= count + 1;
    end
endmodule

// ALU module
module alu(
    input wire [7:0] a,
    input wire [7:0] b,
    input wire [2:0] op,
    output reg [7:0] result,
    output reg zero
);
    always @(*) begin
        case (op)
            3'b000: result = a + b;  // ADD
            3'b001: result = a - b;  // SUB
            3'b010: result = a & b;  // AND
            3'b011: result = a | b;  // OR
            3'b100: result = a ^ b;  // XOR
            3'b101: result = ~a;     // NOT
            default: result = 8'b0;
        endcase

        zero = (result == 8'b0);
    end
endmodule

// Test bench module
module counter_tb;
    reg clk;
    reg reset;
    reg enable;
    wire [7:0] count;

    counter uut (
        .clk(clk),
        .reset(reset),
        .enable(enable),
        .count(count)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Test procedure task
    task run_test;
        input [7:0] expected;
        begin
            @(posedge clk);
            if (count !== expected)
                $display("Error: count = %d, expected = %d", count, expected);
        end
    endtask

    // Helper function
    function [7:0] double_value;
        input [7:0] val;
        begin
            double_value = val << 1;
        end
    endfunction

    // Main test sequence
    initial begin
        reset = 1;
        enable = 0;
        #10 reset = 0;
        #10 enable = 1;
        #100 enable = 0;
        #10 $finish;
    end
endmodule
